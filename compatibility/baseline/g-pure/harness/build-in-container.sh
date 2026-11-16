#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

: "${INPUTS_ROOT:?Set INPUTS_ROOT to the directory containing verified archives}"
: "${CASE_OUT:?Set CASE_OUT to a fresh owned case directory}"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$CASE_OUT/logs"
exec > >(tee "$CASE_OUT/logs/build.stdout") 2> >(tee "$CASE_OUT/logs/build.stderr" >&2)

test "$(uname -m)" = x86_64
test "$(getconf GNU_LIBC_VERSION)" = 'glibc 2.17'
test ! -e "$CASE_OUT/source"
test ! -e "$CASE_OUT/sdk"
test ! -e "$CASE_OUT/payload"
mkdir -p "$CASE_OUT/source" "$CASE_OUT/sdk" "$CASE_OUT/payload" "$CASE_OUT/work"
(
    cd "$INPUTS_ROOT"
    sha256sum --check "$SCRIPT_DIR/archive-sha256.txt"
)
mapfile -t SOURCE_MEMBERS < "$SCRIPT_DIR/source-archive-members.txt"
tar --extract --gzip --file "$INPUTS_ROOT/goawk-v1.30.1.tar.gz" \
    --directory "$CASE_OUT/source" --strip-components=1 \
    -- "${SOURCE_MEMBERS[@]}"
tar --extract --gzip --file "$INPUTS_ROOT/go1.27.4.linux-amd64.tar.gz" --directory "$CASE_OUT/sdk"
(
    cd "$CASE_OUT/source"
    sha256sum --check "$SCRIPT_DIR/source-sha256.txt"
)
test "$(head -n 1 "$CASE_OUT/sdk/go/VERSION")" = go1.27.4
chmod -R a-w "$CASE_OUT/source"

uname -a > "$CASE_OUT/logs/kernel.txt"
getconf GNU_LIBC_VERSION > "$CASE_OUT/logs/libc.txt"
cat /etc/os-release > "$CASE_OUT/logs/os-release.txt"
readelf --version > "$CASE_OUT/logs/readelf-version.txt"
file --version > "$CASE_OUT/logs/file-version.txt"
tar --version > "$CASE_OUT/logs/tar-version.txt"
if command -v rpm >/dev/null; then rpm -qa | sort > "$CASE_OUT/logs/rpm-packages.txt"; fi
file "$CASE_OUT/sdk/go/bin/go" > "$CASE_OUT/logs/sdk-file.txt"
readelf -hW "$CASE_OUT/sdk/go/bin/go" > "$CASE_OUT/logs/sdk-elf-header.txt"
readelf -lW "$CASE_OUT/sdk/go/bin/go" > "$CASE_OUT/logs/sdk-elf-program-headers.txt"
readelf -dW "$CASE_OUT/sdk/go/bin/go" > "$CASE_OUT/logs/sdk-elf-dynamic.txt"
sha256sum "$CASE_OUT/sdk/go/bin/go" > "$CASE_OUT/logs/sdk-go-sha256.txt"

GO_BIN="$CASE_OUT/sdk/go/bin/go"
GO_ENV=(env -i PATH="$CASE_OUT/sdk/go/bin:/usr/bin:/bin" HOME="$CASE_OUT/work" LC_ALL=C
    GOROOT="$CASE_OUT/sdk/go" GOPATH="$CASE_OUT/work/gopath" GOCACHE="$CASE_OUT/work/gocache"
    GOMODCACHE="$CASE_OUT/work/gomodcache" GOENV=off GOWORK=off GOTOOLCHAIN=local
    GOTELEMETRY=off CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1
    GOPROXY=off GOSUMDB=off GODEBUG= GOEXPERIMENT= GOMAXPROCS=2 GOFLAGS='-mod=readonly -p=2')
"${GO_ENV[@]}" "$GO_BIN" version | tee "$CASE_OUT/logs/go-version.txt"
test "$(cat "$CASE_OUT/logs/go-version.txt")" = 'go version go1.27.4 linux/amd64'
"${GO_ENV[@]}" "$GO_BIN" env -json > "$CASE_OUT/logs/go-env.json"
(
    cd "$CASE_OUT/source"
    "${GO_ENV[@]}" "$GO_BIN" list -m -json all > "$CASE_OUT/logs/go-modules.json"
    timeout --kill-after=10s 2400s "${GO_ENV[@]}" "$GO_BIN" build \
        -mod=readonly -buildvcs=false -trimpath -o "$CASE_OUT/payload/goawk" .
    sha256sum --check "$SCRIPT_DIR/source-sha256.txt" > "$CASE_OUT/logs/source-recheck.txt"
)
"${GO_ENV[@]}" "$GO_BIN" version -m "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/binary-go-metadata.txt"
file "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/binary-file.txt"
readelf -hW "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/elf-header.txt"
readelf -lW "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/elf-program-headers.txt"
readelf -dW "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/elf-dynamic.txt"
readelf --version-info "$CASE_OUT/payload/goawk" > "$CASE_OUT/logs/elf-version-info.txt"
grep -Eq 'Machine:.*Advanced Micro Devices X86-64' "$CASE_OUT/logs/elf-header.txt"
! grep -q INTERP "$CASE_OUT/logs/elf-program-headers.txt"
! grep -q NEEDED "$CASE_OUT/logs/elf-dynamic.txt"
! grep -q GLIBC_ "$CASE_OUT/logs/elf-version-info.txt"
cp "$CASE_OUT/source/README.md" "$CASE_OUT/source/LICENSE.txt" "$CASE_OUT/payload/"
chmod 755 "$CASE_OUT/payload/goawk"
chmod 644 "$CASE_OUT/payload/README.md" "$CASE_OUT/payload/LICENSE.txt"
BINARY_SHA256=$(sha256sum "$CASE_OUT/payload/goawk" | cut -d ' ' -f 1)
printf '{"case":"G-pure","status":"built","binary_sha256":"%s","elf_interpreter":null,"dt_needed":[],"glibc_symbol_requirements":[],"network_policy":"launcher_must_set_none","cgo_enabled":false,"goamd64":"v1","source_hashes_rechecked":true}\n' \
    "$BINARY_SHA256" > "$CASE_OUT/build-result.json"
