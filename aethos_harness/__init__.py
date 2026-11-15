"""AETHOS Symbiosis v2.1 Deterministic Execution Harness.

Provides:
- BDP-v1 Telepathy Wire encoding/decoding (`bdp_v1_codec`)
- Volatile RAM-Warp C11 ASan/UBSan & Python Pytest verification (`ram_warp_verifier`)
- Deterministic `AETHOS-ZK-V1` cryptographic execution receipts (`zk_receipt`)
"""

from __future__ import annotations

from typing import Tuple, Union

from .bdp_v1_codec import (
    BDPFrame,
    compression_stats,
    decode_bdp,
    encode_bdp,
    estimate_tokens,
    validate_bdp_frame,
)
from .ram_warp_verifier import (
    VerificationResult,
    get_ram_warp_root,
    verify_c11,
    verify_python,
)
from .zk_receipt import (
    ZKReceipt,
    compute_ast_digest,
    generate_receipt,
    verify_receipt,
)

__version__ = "2.1.0"

__all__ = [
    "__version__",
    "BDPFrame",
    "encode_bdp",
    "decode_bdp",
    "validate_bdp_frame",
    "estimate_tokens",
    "compression_stats",
    "VerificationResult",
    "get_ram_warp_root",
    "verify_c11",
    "verify_python",
    "ZKReceipt",
    "compute_ast_digest",
    "generate_receipt",
    "verify_receipt",
    "verify_and_seal",
]


def verify_and_seal(
    source_code: str,
    *,
    language: str = "python",
    bdp_frame: str | None = None,
    test_code: str | None = None,
    secret_key: Union[bytes, str, None] = None,
    prefer_shm: bool = True,
) -> Tuple[VerificationResult, ZKReceipt]:
    """Execute volatile RAM-Warp verification and seal the result with an AETHOS-ZK-V1 receipt."""
    lang = language.strip().lower()
    if bdp_frame is None:
        gate = "ASAN_CLEAN" if lang in ("c", "c11") else "PYTEST_PASS"
        bdp_frame = encode_bdp(
            intent="CODE_VERIFY",
            dom="C_SYSTEMS" if lang in ("c", "c11") else "PYTHON",
            tgt="RAM_WARP_GATE",
            req="MEMORY_SAFE+ZERO_UB" if lang in ("c", "c11") else "AST_VALID+TEST_PASS",
            gate=gate,
        )

    if lang in ("c", "c11"):
        result = verify_c11(source_code, prefer_shm=prefer_shm)
    elif lang in ("python", "py"):
        result = verify_python(source_code, test_code=test_code, prefer_shm=prefer_shm)
    else:
        raise ValueError(f"Unsupported language {language!r}; expected 'c11' or 'python'.")

    receipt = generate_receipt(
        source_code,
        result.exit_code,
        bdp_frame,
        language=lang,
        secret_key=secret_key,
        ast_digest=result.ast_digest or None,
    )
    return result, receipt
