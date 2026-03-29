#!/usr/bin/env python3.10
"""
SVF-MCP Server: Expose SVF static analysis as MCP tools for Cursor AI.

Usage:
    python3.10 mcp_server.py
"""

import sys
import os
import subprocess
import tempfile
import io
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

from fastmcp import FastMCP

# ── Configuration ────────────────────────────────────────────────────────────
LLVM_BIN = os.environ.get(
    "LLVM_BIN",
    "/data1/wjw/SVF-projects/propagate/SVF/llvm-18.1.0.obj/bin",
)
ANALYSIS_DIR = os.environ.get(
    "SVF_ANALYSIS_DIR",
    "/data1/wjw/SVF-projects/Software-Security-Analysis/Assignment-3/Python",
)

CLANG = os.path.join(LLVM_BIN, "clang")
OPT = os.path.join(LLVM_BIN, "opt")

# ── Ensure pysvf and analysis modules are importable ─────────────────────────
if ANALYSIS_DIR not in sys.path:
    sys.path.insert(0, ANALYSIS_DIR)

import pysvf
from Assignment_3 import Assignment3

# ── MCP Server ───────────────────────────────────────────────────────────────
mcp = FastMCP(
    "SVF Bug Finder",
    instructions=(
        "This server provides C/C++ static analysis powered by SVF "
        "(Static Value-Flow Analysis). It can detect buffer overflows, "
        "memory leaks, and other memory safety bugs in C/C++ source code."
    ),
)


def _compile_c_to_ll(source_path: str, include_flags: str = "") -> str:
    """Compile a C/C++ file to LLVM IR (.ll) using clang + opt mem2reg.

    Returns the path to the generated .ll file (in a temp directory).
    """
    source = Path(source_path).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Source file not found: {source}")
    if source.suffix not in (".c", ".cpp", ".cc", ".cxx"):
        raise ValueError(f"Unsupported file type: {source.suffix}. Expected .c/.cpp/.cc/.cxx")

    # Create .ll in a temp directory
    tmp_dir = tempfile.mkdtemp(prefix="svf_mcp_")
    ll_file = os.path.join(tmp_dir, source.stem + ".ll")

    # Step 1: clang → LLVM IR
    clang_cmd = [
        CLANG, "-g", "-S", "-c",
        "-Xclang", "-disable-O0-optnone",
        "-fno-discard-value-names",
        "-emit-llvm",
    ]
    if include_flags:
        clang_cmd.extend(include_flags.split())
    clang_cmd.extend([str(source), "-o", ll_file])

    result = subprocess.run(clang_cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"clang compilation failed:\n{result.stderr}")

    # Step 2: opt mem2reg
    opt_cmd = [OPT, "-S", "-p=mem2reg", ll_file, "-o", ll_file]
    result = subprocess.run(opt_cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"opt mem2reg failed:\n{result.stderr}")

    return ll_file


def _run_svf_analysis(ll_file: str) -> str:
    """Run SVF abstract execution analysis on an .ll file.

    Returns the captured analysis output as a string.
    """
    buf_stdout = io.StringIO()
    buf_stderr = io.StringIO()

    with redirect_stdout(buf_stdout), redirect_stderr(buf_stderr):
        pysvf.buildSVFModule([ll_file])
        pag = pysvf.getPAG()
        analysis = Assignment3(pag)
        analysis.analyse()
        pysvf.releasePAG()

    output = buf_stdout.getvalue()
    # Extract only the meaningful part (from "Buffer Overflow" report onwards)
    report_marker = "######################Buffer Overflow"
    idx = output.find(report_marker)
    if idx != -1:
        return output[idx:]
    # If no overflow section found, return the tail (skip SVF stats)
    lines = output.strip().split("\n")
    # Find the last meaningful section
    for i, line in enumerate(lines):
        if "overflow" in line.lower() or "assert" in line.lower() or "fixpoint" in line.lower():
            return "\n".join(lines[i:])
    return output


@mcp.tool()
def analyze_c_code(
    source_path: str,
    include_flags: str = "",
) -> str:
    """Detect buffer overflow bugs in C/C++ source code using SVF static analysis.

    This tool compiles C/C++ source code to LLVM IR and runs SVF's abstract
    execution engine to detect buffer overflows, out-of-bounds array accesses,
    and other memory safety issues.

    Args:
        source_path: Absolute or relative path to a C/C++ source file (.c, .cpp).
        include_flags: Optional extra clang flags, e.g. "-I/path/to/headers -DDEBUG".

    Returns:
        Analysis report showing detected buffer overflows with source locations.
    """
    try:
        resolved = str(Path(source_path).resolve())
        ll_file = _compile_c_to_ll(resolved, include_flags)
        report = _run_svf_analysis(ll_file)
        if not report.strip():
            return f"No buffer overflow detected in {Path(source_path).name}."
        return report
    except FileNotFoundError as e:
        return f"Error: {e}"
    except RuntimeError as e:
        return f"Error during analysis:\n{e}"
    except Exception as e:
        return f"Unexpected error: {type(e).__name__}: {e}"


@mcp.tool()
def analyze_ll_code(
    ll_path: str,
) -> str:
    """Detect buffer overflow bugs in a pre-compiled LLVM IR file (.ll).

    Use this when you already have an .ll file and want to skip the clang
    compilation step.

    Args:
        ll_path: Path to an LLVM IR file (.ll).

    Returns:
        Analysis report showing detected buffer overflows with source locations.
    """
    try:
        resolved = str(Path(ll_path).resolve())
        if not os.path.exists(resolved):
            return f"Error: File not found: {resolved}"
        report = _run_svf_analysis(resolved)
        if not report.strip():
            return f"No buffer overflow detected in {Path(ll_path).name}."
        return report
    except Exception as e:
        return f"Unexpected error: {type(e).__name__}: {e}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
