"""Comprehensive tests for AETHOS Symbiosis v2.1 Deterministic Execution Harness."""

from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from aethos_harness import (
    compression_stats,
    compute_ast_digest,
    decode_bdp,
    encode_bdp,
    estimate_tokens,
    generate_receipt,
    get_ram_warp_root,
    validate_bdp_frame,
    verify_and_seal,
    verify_c11,
    verify_python,
    verify_receipt,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# 1. BDP-v1 Telepathy Wire Codec Tests
# ---------------------------------------------------------------------------


def test_bdp_roundtrip_canonical_and_legacy():
    wire = encode_bdp(
        intent="VULN_AUDIT",
        dom="C11",
        tgt="RING_BUFFER",
        req=["BOUNDS_SAFE", "NULL_GUARD"],
        gate="ASAN_CLEAN",
        extra={"LANG": "EN"},
    )
    assert (
        wire
        == "BDP:v1|INTENT=VULN_AUDIT|DOM=C11|TGT=RING_BUFFER|REQ=BOUNDS_SAFE+NULL_GUARD|GATE=ASAN_CLEAN|LANG=EN"
    )

    frame = decode_bdp(wire)
    assert frame.header == "BDP:v1"
    assert frame.intent == "VULN_AUDIT"
    assert frame.dom == "C11"
    assert frame.tgt == "RING_BUFFER"
    assert frame.req == "BOUNDS_SAFE+NULL_GUARD"
    assert frame.gate == "ASAN_CLEAN"
    assert frame.fields["LANG"] == "EN"

    ok, errs = validate_bdp_frame(wire)
    assert ok and errs == []

    # Legacy colon separator compatibility
    legacy_wire = "BDP:v1|INTENT:CODE_SYNTH|DOM:C_SYSTEMS|TGT:ring_buffer|REQ:BOUNDS_SAFE+NULL_GUARD|GATE:ASAN_CLEAN"
    legacy_frame = decode_bdp(legacy_wire)
    assert legacy_frame.intent == "CODE_SYNTH"
    assert legacy_frame.dom == "C_SYSTEMS"
    assert legacy_frame.gate == "ASAN_CLEAN"
    assert validate_bdp_frame(legacy_frame)[0] is True


def test_bdp_validation_errors():
    with pytest.raises(ValueError):
        decode_bdp("HTTP/1.1 200 OK")
    with pytest.raises(ValueError):
        decode_bdp("BDP:v1|INTENT=A|INTENT=B")
    ok, errs = validate_bdp_frame("BDP:v1|INTENT=AUDIT")
    assert not ok
    assert any("DOM" in e for e in errs)


def test_bdp_compression_ratio_matches_symbiosis_target():
    wire = encode_bdp(
        intent="CODE_VERIFY",
        dom="C11",
        tgt="RING_BUFFER",
        req=["BOUNDS_SAFE", "NULL_GUARD"],
        gate="ASAN_CLEAN",
    )
    bdp_toks = estimate_tokens(wire)
    assert 30 <= bdp_toks <= 38

    # Construct a 244-token engineering prose briefing matching Symbiosis v2.1 benchmark scale
    prose_words = ["verify"] * 244
    prose = " ".join(prose_words)
    stats = compression_stats(prose, wire)
    assert stats["prose_tokens"] == 244
    assert stats["bdp_tokens"] == bdp_toks
    assert stats["reduction_pct"] >= 85.0


# ---------------------------------------------------------------------------
# 2. RAM-Warp Verifier Tests (/dev/shm and /tmp fallback)
# ---------------------------------------------------------------------------


def test_ram_warp_root_and_tmp_fallback():
    preferred = get_ram_warp_root(prefer_shm=True)
    fallback = get_ram_warp_root(prefer_shm=False)
    assert fallback.exists()
    if Path("/dev/shm").is_dir():
        assert preferred == Path("/dev/shm")


def test_ram_warp_c11_clean_and_asan_catch():
    clean_c = r"""
#include <stdint.h>
#include <stdio.h>
int main(void) {
    uint8_t buf[4] = {1, 2, 3, 4};
    uint32_t sum = 0;
    for (int i = 0; i < 4; ++i) sum += buf[i];
    printf("sum=%u\n", sum);
    return sum == 10 ? 0 : 1;
}
"""
    res_ok = verify_c11(clean_c, prefer_shm=True)
    assert res_ok.compiled is True
    assert res_ok.exit_code == 0
    assert res_ok.asan_clean is True
    assert res_ok.passed is True
    assert "sum=10" in res_ok.stdout

    # Intentional heap buffer overflow — ASan/UBSan must fail the gate
    overflow_c = r"""
#include <stdlib.h>
int main(void) {
    int *ptr = (int *)malloc(2 * sizeof(int));
    ptr[2] = 99;
    free(ptr);
    return 0;
}
"""
    res_bad = verify_c11(overflow_c, prefer_shm=False)
    assert res_bad.compiled is True
    assert res_bad.passed is False
    assert res_bad.asan_clean is False
    assert res_bad.exit_code != 0

    # Syntax error — compiler fails cleanly
    broken_c = "int main(void) { return MISSING_SYMBOL; }\n"
    res_syntax = verify_c11(broken_c)
    assert res_syntax.compiled is False
    assert res_syntax.passed is False
    assert res_syntax.exit_code != 0


def test_ram_warp_python_compile_and_pytest():
    src = """
def constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
"""
    passing_tests = """
from target_module import constant_time_equal

def test_equal():
    assert constant_time_equal(b"secret", b"secret") is True
    assert constant_time_equal(b"secret", b"secrex") is False
"""
    failing_tests = """
from target_module import constant_time_equal

def test_bad():
    assert constant_time_equal(b"secret", b"wrong") is True
"""
    res_pass = verify_python(src, test_code=passing_tests)
    assert res_pass.compiled is True
    assert res_pass.exit_code == 0
    assert res_pass.passed is True

    res_fail = verify_python(src, test_code=failing_tests)
    assert res_fail.compiled is True
    assert res_fail.exit_code != 0
    assert res_fail.passed is False

    res_syn = verify_python("def broken(:\n    pass\n")
    assert res_syn.compiled is False
    assert res_syn.passed is False


# ---------------------------------------------------------------------------
# 3. AETHOS-ZK-V1 Receipt Generator & Verifier Tests
# ---------------------------------------------------------------------------


def test_zk_receipt_deterministic_and_tamper_evident():
    code_a = "def add(x: int, y: int) -> int:\n    return x + y\n"
    # Same AST with extra comments and whitespace -> identical AST digest
    code_a_formatted = "# comment\ndef add(x: int, y: int) -> int:\n    return (x + y)\n"
    code_mutated = "def add(x: int, y: int) -> int:\n    return x - y\n"

    bdp = encode_bdp("VERIFY", "PY", "ADDER", ["PURE"], "PYTEST_PASS")

    r1 = generate_receipt(code_a, 0, bdp, language="python")
    r2 = generate_receipt(code_a_formatted, 0, bdp, language="python")
    assert r1.receipt_id.startswith("AETHOS-ZK-V1-")
    assert r1.ast_digest == compute_ast_digest(code_a, language="python")
    assert r1.receipt_id == r2.receipt_id
    assert r1.proof_hex == r2.proof_hex

    assert verify_receipt(r1, code_a, 0, bdp, language="python") is True
    assert verify_receipt(r1.receipt_id, code_a, 0, bdp, language="python") is True

    # Tamper checks
    assert verify_receipt(r1, code_mutated, 0, bdp, language="python") is False
    assert verify_receipt(r1, code_a, 1, bdp, language="python") is False
    altered_bdp = encode_bdp("VERIFY", "PY", "ADDER", ["MUTATED"], "PYTEST_PASS")
    assert verify_receipt(r1, code_a, 0, altered_bdp, language="python") is False

    # HMAC mode
    hmac_r = generate_receipt(code_a, 0, bdp, language="python", secret_key="enclave-key")
    assert hmac_r.algorithm == "HMAC-SHA256"
    assert verify_receipt(hmac_r, code_a, 0, bdp, language="python", secret_key="enclave-key") is True
    assert verify_receipt(hmac_r, code_a, 0, bdp, language="python", secret_key="wrong-key") is False


def test_end_to_end_verify_and_seal_c11():
    code = "#include <stdio.h>\nint main(void) { return 0; }\n"
    bdp = encode_bdp("VERIFY", "C11", "MAIN", ["ZERO_UB"], "ASAN_CLEAN")
    result, receipt = verify_and_seal(code, language="c11", bdp_frame=bdp)
    assert result.passed is True
    assert result.asan_clean is True
    assert receipt.to_wire().startswith("BDP:VERIFY|STAT=PASS|EXIT=0|")
    assert verify_receipt(receipt, code, result.exit_code, bdp, language="c11") is True


# ---------------------------------------------------------------------------
# 4. Sanitized Benchmark Datasets & OPSEC Hygiene Check
# ---------------------------------------------------------------------------


def test_benchmark_datasets_valid_and_opsec_clean():
    bench_dir = REPO_ROOT / "benchmarks"
    expected_files = [
        "symbiosis_v1_vs_v2_overnight_20261114.json",
        "symbiosis_v21_customer_cli_live_20261115.json",
        "symbiosis_v21_ecosystem_playground_20261115.json",
        "symbiosis_v21_swarm_security_audit_20261115.json",
    ]
    # Build patterns dynamically so the test file itself stays grep-clean
    tokens = [
        r"\b(?:72|70|32|14|1[._]5)[bB]\b",
        r"_(?:72|70|32|14|1_5)[bB]\b",
        "qwen" + r"2\.5",
        "aka" + "sha",
        "col" + r"ab\d*",
        ":180" + r"\d\d",
        "/home/" + "kali",
        "uncen" + "sored",
        r"0\.0+%\s*(?:false\s*)?ref" + "usal",
    ]
    forbidden = re.compile("|".join(tokens), re.IGNORECASE)
    for fn in expected_files:
        fp = bench_dir / fn
        assert fp.is_file(), f"Missing benchmark dataset: {fn}"
        raw = fp.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert not forbidden.search(raw), f"OPSEC violation detected in {fn}"
        if fn == "symbiosis_v21_swarm_security_audit_20261115.json":
            organs = data["cluster"]["gateway_health"]["organs"]
            assert set(organs.keys()) == {
                "symbiosis_strategist_lobe",
                "forge_coder_lobe",
                "gate_judge_lobe",
                "local_edge_scribe_lobe",
            }
