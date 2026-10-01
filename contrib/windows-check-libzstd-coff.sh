#!/bin/bash
# Fail the link if libzstd.a is not a MinGW COFF archive.
# ZSTD_trace_* refs mean the objects were built with ZSTD_HAVE_WEAK_SYMBOLS,
# which zstd enables only for ELF and explicitly disables for MinGW.
set -eu
A="${1:?archive}"
echo "== libzstd format =="
x86_64-w64-mingw32-objdump -f "$A" | awk '/file format/ {print}' | sort | uniq -c
if x86_64-w64-mingw32-objdump -f "$A" | grep -q 'file format elf'; then
    echo "libzstd contains ELF members (host compiler). Refusing to link."
    exit 1
fi
x86_64-w64-mingw32-objdump -f "$A" | grep -q 'file format pe-x86-64'
if x86_64-w64-mingw32-nm -A "$A" | grep -E ' U ZSTD_trace_' > /tmp/zstd-trace-refs.txt; then
    echo "libzstd references ZSTD_trace_* (not a MinGW build; ZSTD_TRACE is ELF-only)"
    head -n 30 /tmp/zstd-trace-refs.txt
    exit 1
fi
echo "libzstd is pe-x86-64 and has no ZSTD_trace refs"
