#!/usr/bin/env python3.10
"""Quick local test: call the analysis functions directly (no MCP transport)."""

import sys
import os

# Ensure the MCP server module is importable
sys.path.insert(0, os.path.dirname(__file__))

from mcp_server import _compile_c_to_ll, _run_svf_analysis

TEST_C = "/data1/wjw/SVF-projects/Software-Security-Analysis/Assignment-3/Tests/buf/test1.c"
TEST_LL = "/data1/wjw/SVF-projects/Software-Security-Analysis/Assignment-3/Tests/buf/test1.ll"


def test_from_c():
    print("=" * 60)
    print("TEST 1: Analyze from C source (test1.c)")
    print("=" * 60)
    ll = _compile_c_to_ll(TEST_C)
    print(f"Compiled to: {ll}")
    report = _run_svf_analysis(ll)
    print(report)
    assert "Buffer overflow" in report.lower() or "Buffer Overflow" in report
    print("[PASS] Buffer overflow detected from .c file\n")


def test_from_ll():
    print("=" * 60)
    print("TEST 2: Analyze from .ll file (test1.ll)")
    print("=" * 60)
    report = _run_svf_analysis(TEST_LL)
    print(report)
    assert "Buffer overflow" in report.lower() or "Buffer Overflow" in report
    print("[PASS] Buffer overflow detected from .ll file\n")


if __name__ == "__main__":
    test_from_c()
    test_from_ll()
    print("All tests passed!")
