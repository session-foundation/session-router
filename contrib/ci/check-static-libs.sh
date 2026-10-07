#!/usr/bin/env bash

# Script used by CI to check that a statically built Session Router only links against the expected
# base system libraries.  Expects to be run with pwd of the project directory with a build in
# `build` or $1 (if given).

set -o errexit

build=${1:-build}

if ldd ${build}/session-router | grep -Ev '(linux-vdso|ld-linux-(x86-64|armhf|aarch64)|lib(pthread|dl|rt|stdc\+\+|gcc_s|c|m))\.so'; then
    echo -e "\n\n\n\n\e[31;1mSession Router links to unexpected libraries\e[0m\n\n\n"
    exit 1
fi

echo -e "\n\n\n\n\e[32;1mNo unexpected linked libraries found\e[0m\n\n\n"
