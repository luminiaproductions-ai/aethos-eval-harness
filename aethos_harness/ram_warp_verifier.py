"""Volatile RAM-Warp (/dev/shm with /tmp fallback) deterministic execution gate."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, Sequence

from .zk_receipt import compute_ast_digest

_SANITIZER_ERROR_MARKERS = (
    "AddressSanitizer",
    "LeakSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "ERROR: AddressSanitizer",
)


@dataclass(frozen=True)
class VerificationResult:
    """Structured result from the volatile RAM-Warp execution gate."""

    language: str
    passed: bool
    exit_code: int
    asan_clean: bool
    compiled: bool
    ast_digest: str
    compile_ms: float
    run_ms: float
    workspace_root: str
    stdout: str
    stderr: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "passed": self.passed,
            "exit_code": self.exit_code,
            "asan_clean": self.asan_clean,
            "compiled": self.compiled,
            "ast_digest": self.ast_digest,
            "compile_ms": self.compile_ms,
            "run_ms": self.run_ms,
            "workspace_root": self.workspace_root,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def get_ram_warp_root(prefer_shm: bool = True) -> Path:
    """Return ``/dev/shm`` when writable/executable, otherwise fall back to ``/tmp``."""
    if prefer_shm:
        shm = Path("/dev/shm")
        if shm.is_dir() and os.access(shm, os.W_OK | os.X_OK):
            return shm
    return Path(tempfile.gettempdir())


def _has_sanitizer_error(stderr: str) -> bool:
    return any(marker in stderr for marker in _SANITIZER_ERROR_MARKERS)


def verify_c11(
    source_code: str,
    *,
    extra_flags: Sequence[str] | None = None,
    run_binary: bool = True,
    stdin_data: str = "",
    timeout_s: float = 10.0,
    prefer_shm: bool = True,
    compiler: str = "gcc",
) -> VerificationResult:
    """Compile and optionally execute C11 code in volatile RAM with ASan & UBSan."""
    if not shutil.which(compiler):
        raise FileNotFoundError(f"C compiler {compiler!r} not found on PATH.")

    root = get_ram_warp_root(prefer_shm=prefer_shm)
    ast_digest = compute_ast_digest(source_code, language="c11")

    with tempfile.TemporaryDirectory(prefix="aethos_warp_c11_", dir=str(root)) as warp_dir:
        src_path = Path(warp_dir) / "main.c"
        bin_path = Path(warp_dir) / "main.out"
        src_path.write_text(source_code, encoding="utf-8")

        cmd = [
            compiler,
            "-std=c11",
            "-O3",
            "-Wall",
            "-Wextra",
            "-fsanitize=address,undefined",
            str(src_path),
            "-o",
            str(bin_path),
        ]
        if extra_flags:
            cmd.extend(extra_flags)

        t0 = time.perf_counter()
        comp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        compile_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        if comp.returncode != 0:
            return VerificationResult(
                language="c11",
                passed=False,
                exit_code=comp.returncode,
                asan_clean=False,
                compiled=False,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=0.0,
                workspace_root=str(root),
                stdout=comp.stdout,
                stderr=comp.stderr,
            )

        if not run_binary:
            return VerificationResult(
                language="c11",
                passed=True,
                exit_code=0,
                asan_clean=True,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=0.0,
                workspace_root=str(root),
                stdout=comp.stdout,
                stderr=comp.stderr,
            )

        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=1"

        t1 = time.perf_counter()
        try:
            proc = subprocess.run(
                [str(bin_path)],
                input=stdin_data,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout_s,
                check=False,
            )
            run_ms = round((time.perf_counter() - t1) * 1000.0, 2)
            sanitizer_hit = _has_sanitizer_error(proc.stderr)
            asan_clean = proc.returncode == 0 and not sanitizer_hit
            return VerificationResult(
                language="c11",
                passed=asan_clean,
                exit_code=proc.returncode,
                asan_clean=asan_clean,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=run_ms,
                workspace_root=str(root),
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired as exc:
            run_ms = round((time.perf_counter() - t1) * 1000.0, 2)
            return VerificationResult(
                language="c11",
                passed=False,
                exit_code=124,
                asan_clean=False,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=run_ms,
                workspace_root=str(root),
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=f"Execution timed out after {timeout_s}s.",
            )


def verify_python(
    source_code: str,
    *,
    test_code: str | None = None,
    timeout_s: float = 15.0,
    prefer_shm: bool = True,
) -> VerificationResult:
    """Validate Python syntax/AST, run ``py_compile``, and execute ``pytest`` in RAM-Warp."""
    root = get_ram_warp_root(prefer_shm=prefer_shm)

    try:
        ast_digest = compute_ast_digest(source_code, language="python")
    except SyntaxError as exc:
        return VerificationResult(
            language="python",
            passed=False,
            exit_code=1,
            asan_clean=True,
            compiled=False,
            ast_digest="",
            compile_ms=0.0,
            run_ms=0.0,
            workspace_root=str(root),
            stdout="",
            stderr=f"SyntaxError: {exc}",
        )

    with tempfile.TemporaryDirectory(prefix="aethos_warp_py_", dir=str(root)) as warp_dir:
        mod_path = Path(warp_dir) / "target_module.py"
        mod_path.write_text(source_code, encoding="utf-8")

        t0 = time.perf_counter()
        comp = subprocess.run(
            [sys.executable, "-m", "py_compile", str(mod_path)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        compile_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        if comp.returncode != 0:
            return VerificationResult(
                language="python",
                passed=False,
                exit_code=comp.returncode,
                asan_clean=True,
                compiled=False,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=0.0,
                workspace_root=str(root),
                stdout=comp.stdout,
                stderr=comp.stderr,
            )

        pytest_target: Path | None = None
        if test_code is not None:
            test_path = Path(warp_dir) / "test_target.py"
            test_path.write_text(test_code, encoding="utf-8")
            pytest_target = test_path
        elif "def test_" in source_code:
            pytest_target = mod_path

        if pytest_target is None:
            return VerificationResult(
                language="python",
                passed=True,
                exit_code=0,
                asan_clean=True,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=0.0,
                workspace_root=str(root),
                stdout=comp.stdout,
                stderr=comp.stderr,
            )

        env = os.environ.copy()
        existing_pp = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{warp_dir}:{existing_pp}" if existing_pp else warp_dir

        t1 = time.perf_counter()
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(pytest_target)],
                cwd=warp_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
            run_ms = round((time.perf_counter() - t1) * 1000.0, 2)
            return VerificationResult(
                language="python",
                passed=proc.returncode == 0,
                exit_code=proc.returncode,
                asan_clean=True,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=run_ms,
                workspace_root=str(root),
                stdout=proc.stdout,
                stderr=proc.stderr,
            )
        except subprocess.TimeoutExpired:
            run_ms = round((time.perf_counter() - t1) * 1000.0, 2)
            return VerificationResult(
                language="python",
                passed=False,
                exit_code=124,
                asan_clean=True,
                compiled=True,
                ast_digest=ast_digest,
                compile_ms=compile_ms,
                run_ms=run_ms,
                workspace_root=str(root),
                stdout="",
                stderr=f"Pytest execution timed out after {timeout_s}s.",
            )
