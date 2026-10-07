#!/usr/bin/env bash
test "x$IGNORE" != "x" && exit 0

. $(dirname $0)/../format-version.sh

repo=$(readlink -e $(dirname $0)/../../)
$CLANG_FORMAT -i $(find $repo/jni $repo/src $repo/include $repo/pybind | grep -E '\.[hc](pp)?$')
git --no-pager diff --exit-code --color || (echo -ne '\n\n\e[31;1mLint check failed; please run ./contrib/format.sh\e[0m\n\n' ; exit 1)
