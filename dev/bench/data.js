window.BENCHMARK_DATA = {
  "lastUpdate": 1749589658599,
  "repoUrl": "https://github.com/jsturtevant/hyperlight-1",
  "entries": {
    "Hyperlight Benchmarks (Linux - kvm - )": [
      {
        "commit": {
          "author": {
            "name": "James Sturtevant",
            "username": "jsturtevant",
            "email": "jsturtevant@gmail.com"
          },
          "committer": {
            "name": "James Sturtevant",
            "username": "jsturtevant",
            "email": "jsturtevant@gmail.com"
          },
          "id": "6fbdf5df76bb0b3c0ee01e99e0bd1c5b186543de",
          "message": "update\n\nSigned-off-by: James Sturtevant <jsturtevant@gmail.com>",
          "timestamp": "2025-06-10T20:28:31Z",
          "url": "https://github.com/jsturtevant/hyperlight-1/commit/6fbdf5df76bb0b3c0ee01e99e0bd1c5b186543de"
        },
        "date": 1749589658094,
        "tool": "cargo",
        "benches": [
          {
            "name": "guest_functions/guest_call",
            "value": 23650,
            "range": "± 1299",
            "unit": "ns/iter"
          },
          {
            "name": "guest_functions/guest_call_with_reset",
            "value": 45731,
            "range": "± 2055",
            "unit": "ns/iter"
          },
          {
            "name": "guest_functions/guest_call_with_large_parameters",
            "value": 1266770568,
            "range": "± 89606375",
            "unit": "ns/iter"
          },
          {
            "name": "guest_functions/guest_call_with_call_to_host_function",
            "value": 184755,
            "range": "± 13043",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_uninitialized_sandbox",
            "value": 352593,
            "range": "± 18386",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_uninitialized_sandbox_and_drop",
            "value": 415910,
            "range": "± 4817",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_sandbox",
            "value": 1772236,
            "range": "± 92423",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_sandbox_and_drop",
            "value": 12272541,
            "range": "± 5198348",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_sandbox_and_call_context",
            "value": 2253551,
            "range": "± 297884",
            "unit": "ns/iter"
          },
          {
            "name": "sandboxes/create_sandbox_and_call_context_and_drop",
            "value": 16656497,
            "range": "± 6413579",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}