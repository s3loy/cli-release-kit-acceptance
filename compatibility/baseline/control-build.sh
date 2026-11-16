#!/usr/bin/env bash
set -euo pipefail
cd /out
test "$(getconf GNU_LIBC_VERSION)" = "glibc 2.17"
cc --version > compiler.txt
ld --version > linker.txt
lld=/sdk/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld
"$lld" -flavor gnu --version > rust-lld.txt
cc -O0 -fno-builtin -fPIC -c high.c -o high.o
"$lld" -flavor gnu -shared -soname libhigh.so high.o /new/libc.so.6 -o libhigh.so
cc -O0 main.c -L/out -Wl,--no-as-needed -lhigh -Wl,--allow-shlib-undefined \
  -Wl,-rpath,'$ORIGIN' -o control
readelf -W -d control > main.dynamic
readelf -W --version-info control > main.versions
readelf -W -d libhigh.so > library.dynamic
readelf -W --version-info libhigh.so > library.versions
