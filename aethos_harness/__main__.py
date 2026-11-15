"""CLI self-check demonstrating BDP-v1 compression, RAM-Warp ASan/Pytest, and AETHOS-ZK-V1."""

from __future__ import annotations

import json

from . import (
    __version__,
    compression_stats,
    decode_bdp,
    encode_bdp,
    verify_and_seal,
    verify_receipt,
)

_SAMPLE_PROSE = (
    "Attention Sovereign Analysis Stage and Code Synthesis Stage: please execute a comprehensive "
    "memory safety audit and defensive remediation pass across the C11 lock-free ring buffer "
    "implementation deployed inside the sovereign edge telemetry bridge. You are required to "
    "validate every pointer dereference against null inputs, protect head and tail index "
    "wraparound arithmetic against unsigned integer overflow and capacity overrun conditions, "
    "enforce strict ring index masking power-of-two bounds, verify zero race conditions under "
    "atomic acquire release semantics across concurrent producer and consumer threads, "
    "guarantee zero uninitialized heap reads or out-of-bounds buffer writes under concurrent "
    "producer and consumer pressure, preserve strict O(1) deterministic push and pop latency "
    "without blocking mutex primitives, confirm constant-time comparison hygiene on control "
    "plane authentication checks, prevent integer truncation across buffer length arguments, "
    "enforce explicit memory barrier ordering for single-producer single-consumer slots, "
    "verify zero memory leaks under repeated stress loops, and compile the final candidate "
    "module inside our volatile RAM-Warp sandbox under GCC C11 with optimization level O3 "
    "and full AddressSanitizer plus UndefinedBehaviorSanitizer instrumentation enabled. "
    "Coordinate all constraints across the Compiler Verification Gate and Edge Intake Stage without "
    "skipping defensive bounds checks, edge case boundary validation, or compiler error checks, "
    "and emit a deterministic cryptographic AETHOS-ZK-V1 execution attestation upon verifying "
    "clean exit status zero from the compiled binary."
)

_SAMPLE_C11 = r"""
#include <stdint.h>
#include <stdio.h>

static uint8_t ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

int main(void) {
    const uint8_t k1[4] = {0x10, 0x20, 0x30, 0x40};
    const uint8_t k2[4] = {0x10, 0x20, 0x30, 0x40};
    return ct_equal(k1, k2, 4) ? 0 : 1;
}
"""


def main() -> int:
    frame = encode_bdp(
        intent="CODE_VERIFY",
        dom="C11",
        tgt="RING_BUFFER",
        req=["BOUNDS_SAFE", "NULL_GUARD"],
        gate="ASAN_CLEAN",
    )
    decoded = decode_bdp(frame)
    stats = compression_stats(_SAMPLE_PROSE, frame)

    result, receipt = verify_and_seal(_SAMPLE_C11, language="c11", bdp_frame=frame)
    verified = verify_receipt(receipt, _SAMPLE_C11, result.exit_code, frame, language="c11")

    summary = {
        "harness_version": __version__,
        "bdp_frame": decoded.raw,
        "compression": stats,
        "ram_warp": result.to_dict(),
        "zk_receipt": receipt.to_dict(),
        "zk_wire": receipt.to_wire(),
        "zk_verified": verified,
    }
    print(json.dumps(summary, indent=2))
    return 0 if (result.passed and verified) else 1


if __name__ == "__main__":
    raise SystemExit(main())
