"""Deterministic AETHOS-ZK-V1 cryptographic receipt generator and verifier."""

from __future__ import annotations

import ast
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Mapping, Union

from .bdp_v1_codec import decode_bdp

ZK_VERSION = "AETHOS-ZK-V1"
_C_TOKEN_RE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z0-9_]*|[0-9]+(?:\.[0-9]+)?|\S'
)
_C_COMMENT_OR_STR_RE = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|//[^\n]*|/\*[\s\S]*?\*/'
)


@dataclass(frozen=True)
class ZKReceipt:
    """Deterministic cryptographic attestation binding AST, exit code, and BDP frame."""

    version: str
    algorithm: str
    receipt_id: str
    proof_hex: str
    ast_digest: str
    compiler_exit_code: int
    bdp_frame: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "receipt_id": self.receipt_id,
            "proof_hex": self.proof_hex,
            "ast_digest": self.ast_digest,
            "compiler_exit_code": self.compiler_exit_code,
            "bdp_frame": self.bdp_frame,
        }

    def to_wire(self) -> str:
        status = "PASS" if self.compiler_exit_code == 0 else "FAIL"
        return (
            f"BDP:VERIFY|STAT={status}|EXIT={self.compiler_exit_code}"
            f"|AST={self.ast_digest[:12]}|RECEIPT={self.receipt_id}"
        )


def _strip_c_comments(source_code: str) -> str:
    """Strip C/C++ comments while preserving quoted string and char literals."""
    return _C_COMMENT_OR_STR_RE.sub(lambda m: m.group(1) or " ", source_code)


def compute_ast_digest(source_code: str, language: str = "python") -> str:
    """Compute a canonical SHA-256 digest of the source code structure.

    - ``python``: parses the Python AST (ignoring whitespace and comments).
    - ``c11`` / ``c``: strips comments and normalizes C tokens (ignoring formatting).
    """
    lang = language.strip().lower()
    if lang in ("python", "py"):
        tree = ast.parse(source_code)
        canonical = ast.dump(tree, include_attributes=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if lang in ("c", "c11", "cpp"):
        stripped = _strip_c_comments(source_code)
        tokens = _C_TOKEN_RE.findall(stripped)
        canonical = " ".join(tokens)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    raise ValueError(f"Unsupported language for AST digest: {language!r}")


def _canonical_payload_bytes(
    ast_digest: str, compiler_exit_code: int, bdp_frame: str
) -> bytes:
    payload = {
        "version": ZK_VERSION,
        "ast_digest": ast_digest,
        "compiler_exit_code": int(compiler_exit_code),
        "bdp_frame": bdp_frame,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _normalize_key(secret_key: Union[bytes, str, None]) -> bytes | None:
    if secret_key is None:
        return None
    if isinstance(secret_key, str):
        return secret_key.encode("utf-8")
    return bytes(secret_key)


def generate_receipt(
    source_code: str,
    compiler_exit_code: int,
    bdp_frame: str,
    *,
    language: str = "python",
    secret_key: Union[bytes, str, None] = None,
    ast_digest: str | None = None,
) -> ZKReceipt:
    """Generate a deterministic ``AETHOS-ZK-V1-<HMAC/SHA256>`` verification receipt."""
    parsed_bdp = decode_bdp(bdp_frame)
    resolved_ast = ast_digest or compute_ast_digest(source_code, language=language)
    payload_bytes = _canonical_payload_bytes(
        resolved_ast, compiler_exit_code, parsed_bdp.raw
    )

    key_bytes = _normalize_key(secret_key)
    if key_bytes is not None:
        algorithm = "HMAC-SHA256"
        proof_hex = hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
    else:
        algorithm = "SHA256"
        proof_hex = hashlib.sha256(
            f"{ZK_VERSION}|".encode("utf-8") + payload_bytes
        ).hexdigest()

    receipt_id = f"{ZK_VERSION}-{proof_hex[:16].upper()}"
    return ZKReceipt(
        version=ZK_VERSION,
        algorithm=algorithm,
        receipt_id=receipt_id,
        proof_hex=proof_hex,
        ast_digest=resolved_ast,
        compiler_exit_code=int(compiler_exit_code),
        bdp_frame=parsed_bdp.raw,
    )


def verify_receipt(
    receipt: Union[ZKReceipt, Mapping[str, Any], str],
    source_code: str,
    compiler_exit_code: int,
    bdp_frame: str,
    *,
    language: str = "python",
    secret_key: Union[bytes, str, None] = None,
    ast_digest: str | None = None,
) -> bool:
    """Deterministically verify an ``AETHOS-ZK-V1`` receipt against code, exit code, and BDP."""
    try:
        expected = generate_receipt(
            source_code,
            compiler_exit_code,
            bdp_frame,
            language=language,
            secret_key=secret_key,
            ast_digest=ast_digest,
        )
    except (SyntaxError, ValueError):
        return False

    if isinstance(receipt, str):
        return hmac.compare_digest(receipt.strip().upper(), expected.receipt_id)

    if isinstance(receipt, ZKReceipt):
        return hmac.compare_digest(receipt.proof_hex, expected.proof_hex) and hmac.compare_digest(
            receipt.receipt_id, expected.receipt_id
        )

    if isinstance(receipt, Mapping):
        provided_hex = str(receipt.get("proof_hex", ""))
        provided_id = str(receipt.get("receipt_id", ""))
        if provided_hex and not hmac.compare_digest(provided_hex, expected.proof_hex):
            return False
        if provided_id:
            return hmac.compare_digest(provided_id.upper(), expected.receipt_id)
        return bool(provided_hex)

    return False
