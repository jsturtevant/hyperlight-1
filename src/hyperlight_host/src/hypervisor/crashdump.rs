/*
Copyright 2025 The Hyperlight Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::cmp::min;
use std::io::Write;

use chrono;
use elfcore::{
    ArchComponentState, ArchState, CoreDumpBuilder, CoreError, Elf64_Auxv, ProcessInfoSource,
    ReadProcessMemory, ThreadView, VaProtection, VaRegion,
};
#[cfg(feature = "init-paging")]
use hyperlight_common::vmem::{self, BasicMapping, MappingKind};

use crate::hypervisor::hyperlight_vm::HyperlightVm;
#[cfg(feature = "init-paging")]
use crate::mem::layout::SandboxMemoryLayout;
use crate::mem::memory_region::{MemoryRegion, MemoryRegionFlags, MemoryRegionType};
#[cfg(feature = "init-paging")]
use crate::mem::shared_mem::{GuestSharedMemory, SharedMemory};
use crate::{Result, new_error};

/// This constant is used to identify the XSAVE state in the core dump
const NT_X86_XSTATE: u32 = 0x202;
/// This constant identifies the entry point of the program in an Auxiliary Vector
/// note of ELF. This tells a debugger whether the entry point of the program changed
/// so it can load the symbols correctly.
const AT_ENTRY: u64 = 9;
/// This constant is used to mark the end of the Auxiliary Vector note
const AT_NULL: u64 = 0;
/// The PID of the core dump process - this is a placeholder value
const CORE_DUMP_PID: i32 = 1;
/// The page size of the core dump
const CORE_DUMP_PAGE_SIZE: usize = 0x1000;

/// Reads page table entries from snapshot and scratch `GuestSharedMemory` regions.
///
/// This is used to walk the guest page tables during crash dump generation,
/// so we can discover all GVA→GPA mappings and emit the correct virtual addresses
/// in the ELF core dump.
#[cfg(feature = "init-paging")]
struct CrashDumpPtReader {
    /// Host pointer to the start of the snapshot's usable memory
    snapshot_host_base: *const u8,
    /// GPA at which the snapshot memory is mapped (BASE_ADDRESS)
    snapshot_gpa_base: u64,
    /// Size of the snapshot memory in bytes
    snapshot_size: usize,
    /// Host pointer to the start of the scratch's usable memory
    scratch_host_base: *const u8,
    /// GPA at which the scratch memory is mapped
    scratch_gpa_base: u64,
    /// Size of the scratch memory in bytes
    scratch_size: usize,
    /// Root page table physical address (CR3)
    root_pt: u64,
}

#[cfg(feature = "init-paging")]
impl vmem::TableReadOps for CrashDumpPtReader {
    type TableAddr = u64;

    fn entry_addr(addr: u64, offset: u64) -> u64 {
        addr + offset
    }

    unsafe fn read_entry(&self, addr: u64) -> u64 {
        // Check if GPA is in the snapshot region
        if addr >= self.snapshot_gpa_base
            && addr + 8 <= self.snapshot_gpa_base + self.snapshot_size as u64
        {
            let offset = (addr - self.snapshot_gpa_base) as usize;
            // Safety: offset is bounds-checked above, and the pointer is valid
            // for the lifetime of the crash dump operation
            unsafe {
                let ptr = self.snapshot_host_base.add(offset);
                (ptr as *const u64).read_unaligned()
            }
        }
        // Check if GPA is in the scratch region
        else if addr >= self.scratch_gpa_base
            && addr + 8 <= self.scratch_gpa_base + self.scratch_size as u64
        {
            let offset = (addr - self.scratch_gpa_base) as usize;
            // Safety: offset is bounds-checked above, and the pointer is valid
            // for the lifetime of the crash dump operation
            unsafe {
                let ptr = self.scratch_host_base.add(offset);
                (ptr as *const u64).read_unaligned()
            }
        } else {
            // Not in any known region; return 0 (not-present PTE)
            0
        }
    }

    fn to_phys(addr: u64) -> u64 {
        addr
    }

    fn from_phys(addr: u64) -> u64 {
        addr
    }

    fn root_table(&self) -> u64 {
        self.root_pt
    }
}

#[cfg(feature = "init-paging")]
impl AsRef<CrashDumpPtReader> for CrashDumpPtReader {
    fn as_ref(&self) -> &Self {
        self
    }
}

/// Convert a `MappingKind` from the page table walker to `MemoryRegionFlags`.
#[cfg(feature = "init-paging")]
fn mapping_kind_to_flags(kind: &MappingKind) -> MemoryRegionFlags {
    match kind {
        MappingKind::Basic(BasicMapping {
            readable,
            writable,
            executable,
        }) => {
            let mut flags = MemoryRegionFlags::empty();
            if *readable {
                flags |= MemoryRegionFlags::READ;
            }
            if *writable {
                flags |= MemoryRegionFlags::WRITE;
            }
            if *executable {
                flags |= MemoryRegionFlags::EXECUTE;
            }
            flags
        }
        MappingKind::Cow(cow) => {
            let mut flags = MemoryRegionFlags::empty();
            if cow.readable {
                flags |= MemoryRegionFlags::READ;
            }
            if cow.executable {
                flags |= MemoryRegionFlags::EXECUTE;
            }
            flags
        }
    }
}

/// Resolve a GPA to a host memory address by checking the snapshot, scratch,
/// and dynamic mmap regions.
///
/// Returns the host address as a `usize`, or `None` if the GPA is not in any
/// known region.
#[cfg(feature = "init-paging")]
fn resolve_gpa_to_host(
    gpa: u64,
    len: u64,
    snapshot: &GuestSharedMemory,
    snapshot_gpa_base: u64,
    scratch: &GuestSharedMemory,
    scratch_gpa_base: u64,
    mmap_regions: &[MemoryRegion],
) -> Option<usize> {
    let gpa_end = gpa + len;

    // Check snapshot region
    let snap_gpa_end = snapshot_gpa_base + snapshot.mem_size() as u64;
    if gpa >= snapshot_gpa_base && gpa_end <= snap_gpa_end {
        let offset = (gpa - snapshot_gpa_base) as usize;
        return Some(snapshot.base_addr() + offset);
    }

    // Check scratch region
    let scratch_gpa_end = scratch_gpa_base + scratch.mem_size() as u64;
    if gpa >= scratch_gpa_base && gpa_end <= scratch_gpa_end {
        let offset = (gpa - scratch_gpa_base) as usize;
        return Some(scratch.base_addr() + offset);
    }

    // Check dynamic mmap regions
    for rgn in mmap_regions {
        if gpa as usize >= rgn.guest_region.start && gpa_end as usize <= rgn.guest_region.end {
            let offset = gpa as usize - rgn.guest_region.start;
            #[allow(clippy::useless_conversion)]
            let host_start: usize = rgn.host_region.start.into();
            return Some(host_start + offset);
        }
    }

    None
}

/// Walk the guest page tables and produce a list of `MemoryRegion` entries
/// mapped at their virtual addresses (GVAs).
///
/// This is essential for generating core dumps that GDB can use: the ELF
/// program headers need virtual addresses so that GDB can access the stack,
/// code, and heap at the addresses the guest actually uses.
///
/// Contiguous pages with the same flags and contiguous host backing are
/// coalesced into larger regions for efficiency.
#[cfg(feature = "init-paging")]
pub(crate) fn resolve_gva_regions(
    snapshot: &GuestSharedMemory,
    scratch: &GuestSharedMemory,
    mmap_regions: &[MemoryRegion],
    cr3: u64,
) -> Vec<MemoryRegion> {
    let snapshot_gpa_base = SandboxMemoryLayout::BASE_ADDRESS as u64;
    let scratch_gpa_base = hyperlight_common::layout::scratch_base_gpa(scratch.mem_size());

    let reader = CrashDumpPtReader {
        snapshot_host_base: snapshot.base_ptr(),
        snapshot_gpa_base,
        snapshot_size: snapshot.mem_size(),
        scratch_host_base: scratch.base_ptr(),
        scratch_gpa_base,
        scratch_size: scratch.mem_size(),
        root_pt: cr3,
    };

    // Walk the entire virtual address space to discover all mapped pages
    let mappings =
        unsafe { vmem::virt_to_phys(&reader, 0, hyperlight_common::layout::MAX_GVA as u64) };

    // Coalesce contiguous pages with the same flags into larger regions
    let mut regions: Vec<MemoryRegion> = Vec::new();

    for mapping in mappings {
        let flags = mapping_kind_to_flags(&mapping.kind);
        let host_addr = resolve_gpa_to_host(
            mapping.phys_base,
            mapping.len,
            snapshot,
            snapshot_gpa_base,
            scratch,
            scratch_gpa_base,
            mmap_regions,
        );

        let Some(host_addr) = host_addr else {
            // GPA not in any known region; skip this page
            continue;
        };

        let gva_start = mapping.virt_base as usize;
        let gva_end = gva_start + mapping.len as usize;
        let host_end = host_addr + mapping.len as usize;

        // Try to extend the last region if this page is contiguous
        if let Some(last) = regions.last_mut() {
            #[allow(clippy::useless_conversion)]
            let last_host_end: usize = last.host_region.end.into();
            if last.guest_region.end == gva_start
                && last_host_end == host_addr
                && last.flags == flags
            {
                last.guest_region.end = gva_end;
                #[cfg(not(target_os = "windows"))]
                {
                    last.host_region.end = host_end;
                }
                #[cfg(target_os = "windows")]
                {
                    last.host_region.end = crate::mem::memory_region::HostGuestMemoryRegion::add(
                        last.host_region.start,
                        gva_end - last.guest_region.start,
                    );
                }
                continue;
            }
        }

        // Start a new region
        #[cfg(not(target_os = "windows"))]
        let host_region = host_addr..host_end;
        #[cfg(target_os = "windows")]
        let host_region = {
            // For Windows, we need to find the backing region info
            // Fallback: use usize-based addressing
            let base = crate::mem::memory_region::HostRegionBase {
                from_handle: windows::Win32::Foundation::INVALID_HANDLE_VALUE.into(),
                handle_base: 0,
                handle_size: 0,
                offset: host_addr,
            };
            base..crate::mem::memory_region::HostGuestMemoryRegion::add(base, mapping.len as usize)
        };

        regions.push(MemoryRegion {
            guest_region: gva_start..gva_end,
            host_region,
            flags,
            region_type: MemoryRegionType::Code, // Generic type for core dump
        });
    }

    regions
}

/// Structure to hold the crash dump context
/// This structure contains the information needed to create a core dump
#[derive(Debug)]
pub(crate) struct CrashDumpContext {
    regions: Vec<MemoryRegion>,
    regs: [u64; 27],
    xsave: Vec<u8>,
    entry: u64,
    binary: Option<String>,
    filename: Option<String>,
}

impl CrashDumpContext {
    pub(crate) fn new(
        regions: Vec<MemoryRegion>,
        regs: [u64; 27],
        xsave: Vec<u8>,
        entry: u64,
        binary: Option<String>,
        filename: Option<String>,
    ) -> Self {
        Self {
            regions,
            regs,
            xsave,
            entry,
            binary,
            filename,
        }
    }
}

/// Structure that contains the process information for the core dump
/// This serves as a source of information for `elfcore`'s [`CoreDumpBuilder`]
struct GuestView {
    regions: Vec<VaRegion>,
    threads: Vec<ThreadView>,
    aux_vector: Vec<elfcore::Elf64_Auxv>,
}

impl GuestView {
    fn new(ctx: &CrashDumpContext) -> Self {
        // Map the regions to the format `CoreDumpBuilder` expects
        let regions = ctx
            .regions
            .iter()
            .filter(|r| !r.guest_region.is_empty())
            .map(|r| VaRegion {
                begin: r.guest_region.start as u64,
                end: r.guest_region.end as u64,
                offset: <_ as Into<usize>>::into(r.host_region.start) as u64,
                protection: VaProtection {
                    is_private: false,
                    read: r.flags.contains(MemoryRegionFlags::READ),
                    write: r.flags.contains(MemoryRegionFlags::WRITE),
                    execute: r.flags.contains(MemoryRegionFlags::EXECUTE),
                },
                mapped_file_name: None,
            })
            .collect();

        let filename = ctx
            .filename
            .as_ref()
            .map_or("<unknown>".to_string(), |s| s.to_string());

        let cmd = ctx
            .binary
            .as_ref()
            .map_or("<unknown>".to_string(), |s| s.to_string());

        // The xsave state is checked as it can be empty
        let mut components = vec![];
        if !ctx.xsave.is_empty() {
            components.push(ArchComponentState {
                name: "XSAVE",
                note_type: NT_X86_XSTATE,
                note_name: b"LINUX",
                data: ctx.xsave.clone(),
            });
        }

        // Create the thread view
        // The thread view contains the information about the thread
        // NOTE: Some of these fields are not used in the current implementation
        let thread = ThreadView {
            flags: 0, // Kernel flags for the process
            tid: 1,
            uid: 0, // User ID
            gid: 0, // Group ID
            comm: filename,
            ppid: 0,    // Parent PID
            pgrp: 0,    // Process group ID
            nice: 0,    // Nice value
            state: 0,   // Process state
            utime: 0,   // User time
            stime: 0,   // System time
            cutime: 0,  // Children User time
            cstime: 0,  // Children User time
            cursig: 0,  // Current signal
            session: 0, // Session ID of the process
            sighold: 0, // Blocked signal
            sigpend: 0, // Pending signal
            cmd_line: cmd,

            arch_state: Box::new(ArchState {
                gpr_state: ctx.regs.to_vec(),
                components,
            }),
        };

        // Create the auxv vector
        // The first entry is AT_ENTRY, which is the entry point of the program
        // The entry point is the address where the program starts executing
        // This helps the debugger to know that the entry is changed by an offset
        // so the symbols can be loaded correctly.
        // The second entry is AT_NULL, which marks the end of the vector
        let auxv = vec![
            Elf64_Auxv {
                a_type: AT_ENTRY,
                a_val: ctx.entry,
            },
            Elf64_Auxv {
                a_type: AT_NULL,
                a_val: 0,
            },
        ];

        Self {
            regions,
            threads: vec![thread],
            aux_vector: auxv,
        }
    }
}

impl ProcessInfoSource for GuestView {
    fn pid(&self) -> i32 {
        CORE_DUMP_PID
    }
    fn threads(&self) -> &[elfcore::ThreadView] {
        &self.threads
    }
    fn page_size(&self) -> usize {
        CORE_DUMP_PAGE_SIZE
    }
    fn aux_vector(&self) -> Option<&[elfcore::Elf64_Auxv]> {
        Some(&self.aux_vector)
    }
    fn va_regions(&self) -> &[elfcore::VaRegion] {
        &self.regions
    }
    fn mapped_files(&self) -> Option<&[elfcore::MappedFile]> {
        // We don't have mapped files
        None
    }
}

/// Structure that reads the guest memory
/// This structure serves as a custom memory reader for `elfcore`'s
/// [`CoreDumpBuilder`]
struct GuestMemReader {
    regions: Vec<MemoryRegion>,
}

impl GuestMemReader {
    fn new(ctx: &CrashDumpContext) -> Self {
        Self {
            regions: ctx.regions.clone(),
        }
    }
}

impl ReadProcessMemory for GuestMemReader {
    fn read_process_memory(
        &mut self,
        base: usize,
        buf: &mut [u8],
    ) -> std::result::Result<usize, CoreError> {
        for r in self.regions.iter() {
            // Check if the base address is within the guest region
            if base >= r.guest_region.start && base < r.guest_region.end {
                let offset = base - r.guest_region.start;
                let region_slice = unsafe {
                    std::slice::from_raw_parts(
                        <_ as Into<usize>>::into(r.host_region.start) as *const u8,
                        r.guest_region.len(),
                    )
                };

                // Calculate how much we can copy
                let copy_size = min(buf.len(), region_slice.len() - offset);
                if copy_size == 0 {
                    return std::result::Result::Ok(0);
                }

                // Only copy the amount that fits in both buffers
                buf[..copy_size].copy_from_slice(&region_slice[offset..offset + copy_size]);

                // Return the number of bytes copied
                return std::result::Result::Ok(copy_size);
            }
        }

        // If we reach here, we didn't find a matching region
        std::result::Result::Ok(0)
    }
}

/// Create core dump file from the hypervisor information if the sandbox is configured
/// to allow core dumps.
///
/// This function generates an ELF core dump file capturing the hypervisor's state,
/// which can be used for debugging when crashes occur.
/// The location of the core dump file is determined by the `HYPERLIGHT_CORE_DUMP_DIR`
/// environment variable. If not set, it defaults to the system's temporary directory.
///
/// # Arguments
/// * `hv`: Reference to the hypervisor implementation
///
/// # Returns
/// * `Result<()>`: Success or error
pub(crate) fn generate_crashdump(hv: &HyperlightVm) -> Result<()> {
    // Get crash context from hypervisor
    let ctx = hv
        .crashdump_context()
        .map_err(|e| new_error!("Failed to get crashdump context: {:?}", e))?;

    // Get env variable for core dump directory
    let core_dump_dir = std::env::var("HYPERLIGHT_CORE_DUMP_DIR").ok();

    // Compute file path on the filesystem
    let file_path = core_dump_file_path(core_dump_dir);

    let create_dump_file = || {
        // Create the file
        Ok(Box::new(
            std::fs::File::create(&file_path)
                .map_err(|e| new_error!("Failed to create core dump file: {:?}", e))?,
        ) as Box<dyn Write>)
    };

    if let Ok(nbytes) = checked_core_dump(ctx, create_dump_file) {
        if nbytes > 0 {
            println!("Core dump created successfully: {}", file_path);
            log::error!("Core dump file: {}", file_path);
        }
    } else {
        log::error!("Failed to create core dump file");
    }

    Ok(())
}

/// Computes the file path for the core dump file.
///
/// The file path is generated based on the current timestamp and an
/// output directory.
/// If the directory does not exist, it falls back to the system's temp directory.
/// If the variable is not set, it defaults to the system's temporary directory.
/// The filename is formatted as `hl_core_<timestamp>.elf`.
///
/// Arguments:
/// * `dump_dir`: The environment variable value to check for the output directory.
///
/// Returns:
/// * `String`: The file path for the core dump file.
fn core_dump_file_path(dump_dir: Option<String>) -> String {
    // Generate timestamp string for the filename using chrono
    let timestamp = chrono::Local::now()
        .format("%Y%m%d_T%H%M%S%.3f")
        .to_string();

    // Determine the output directory based on environment variable
    let output_dir = if let Some(dump_dir) = dump_dir {
        // Check if the directory exists
        // If it doesn't exist, fall back to the system temp directory
        // This is to ensure that the core dump can be created even if the directory is not set
        if std::path::Path::new(&dump_dir).exists() {
            std::path::PathBuf::from(dump_dir)
        } else {
            log::warn!(
                "Directory \"{}\" does not exist, falling back to temp directory",
                dump_dir
            );
            std::env::temp_dir()
        }
    } else {
        // Fall back to the system temp directory
        std::env::temp_dir()
    };

    // Create the filename with timestamp
    let filename = format!("hl_core_{}.elf", timestamp);
    let file_path = output_dir.join(filename);

    file_path.to_string_lossy().to_string()
}

/// Create core dump from Hypervisor context if the sandbox is configured to allow core dumps.
///
/// Arguments:
/// * `ctx`: Optional crash dump context from the hypervisor. This contains the information
///   needed to create the core dump. If `None`, no core dump will be created.
/// * `get_writer`: Closure that returns a writer to the output destination.
///
/// Returns:
/// * `Result<usize>`: The number of bytes written to the core dump file.
fn checked_core_dump(
    ctx: Option<CrashDumpContext>,
    get_writer: impl FnOnce() -> Result<Box<dyn Write>>,
) -> Result<usize> {
    let mut nbytes = 0;
    // If the HV returned a context it means we can create a core dump
    // This is the case when the sandbox has been configured at runtime to allow core dumps
    if let Some(ctx) = ctx {
        log::info!("Creating core dump file...");

        // Set up data sources for the core dump
        let guest_view = GuestView::new(&ctx);
        let memory_reader = GuestMemReader::new(&ctx);

        // Create and write core dump
        let core_builder = CoreDumpBuilder::from_source(guest_view, memory_reader);

        let writer = get_writer()?;
        // Write the core dump directly to the file
        nbytes = core_builder
            .write(writer)
            .map_err(|e| new_error!("Failed to write core dump: {:?}", e))?;
    }

    Ok(nbytes)
}

/// Test module for the crash dump functionality
#[cfg(test)]
mod test {
    use super::*;

    /// Test the core_dump_file_path function when the environment variable is set to an existing
    /// directory
    #[test]
    fn test_crashdump_file_path_valid() {
        // Get CWD
        let valid_dir = std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .to_string();

        // Call the function
        let path = core_dump_file_path(Some(valid_dir.clone()));

        // Check if the path is correct
        assert!(path.contains(&valid_dir));
    }

    /// Test the core_dump_file_path function when the environment variable is set to an invalid
    /// directory
    #[test]
    fn test_crashdump_file_path_invalid() {
        // Call the function
        let path = core_dump_file_path(Some("/tmp/not_existing_dir".to_string()));

        // Get the temp directory
        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();

        // Check if the path is correct
        assert!(path.contains(&temp_dir));
    }

    /// Test the core_dump_file_path function when the environment is not set
    /// Check against the default temp directory by using the env::temp_dir() function
    #[test]
    fn test_crashdump_file_path_default() {
        // Call the function
        let path = core_dump_file_path(None);

        let temp_dir = std::env::temp_dir().to_string_lossy().to_string();

        // Check if the path is correct
        assert!(path.starts_with(&temp_dir));
    }

    /// Test core is not created when the context is None
    #[test]
    fn test_crashdump_not_created_when_context_is_none() {
        // Call the function with None context
        let result = checked_core_dump(None, || Ok(Box::new(std::io::empty())));

        // Check if the result is ok and the number of bytes is 0
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    /// Test the core dump creation with no regions fails
    #[test]
    fn test_crashdump_write_fails_when_no_regions() {
        // Create a dummy context
        let ctx = CrashDumpContext::new(
            vec![],
            [0; 27],
            vec![],
            0,
            Some("dummy_binary".to_string()),
            Some("dummy_filename".to_string()),
        );

        let get_writer = || Ok(Box::new(std::io::empty()) as Box<dyn Write>);

        // Call the function
        let result = checked_core_dump(Some(ctx), get_writer);

        // Check if the result is an error
        // This should fail because there are no regions
        assert!(result.is_err());
    }

    /// Check core dump with a dummy region to local vec
    /// This test checks if the core dump is created successfully
    #[test]
    fn test_crashdump_dummy_core_dump() {
        let dummy_vec = vec![0; 0x1000];
        use crate::mem::memory_region::{HostGuestMemoryRegion, MemoryRegionKind};
        #[cfg(target_os = "windows")]
        let host_base = crate::mem::memory_region::HostRegionBase {
            from_handle: windows::Win32::Foundation::INVALID_HANDLE_VALUE.into(),
            handle_base: 0,
            handle_size: -1isize as usize,
            offset: dummy_vec.as_ptr() as usize,
        };
        #[cfg(not(target_os = "windows"))]
        let host_base = dummy_vec.as_ptr() as usize;
        let host_end = <HostGuestMemoryRegion as MemoryRegionKind>::add(host_base, dummy_vec.len());
        let regions = vec![MemoryRegion {
            guest_region: 0x1000..0x2000,
            host_region: host_base..host_end,
            flags: MemoryRegionFlags::READ | MemoryRegionFlags::WRITE,
            region_type: crate::mem::memory_region::MemoryRegionType::Code,
        }];
        // Create a dummy context
        let ctx = CrashDumpContext::new(
            regions,
            [0; 27],
            vec![],
            0x1000,
            Some("dummy_binary".to_string()),
            Some("dummy_filename".to_string()),
        );

        let get_writer = || Ok(Box::new(std::io::empty()) as Box<dyn Write>);

        // Call the function
        let result = checked_core_dump(Some(ctx), get_writer);

        // Check if the result is ok and the number of bytes is 0
        assert!(result.is_ok());
        // Check the number of bytes written is more than 0x1000 (the size of the region)
        assert_eq!(result.unwrap(), 0x2000);
    }
}
