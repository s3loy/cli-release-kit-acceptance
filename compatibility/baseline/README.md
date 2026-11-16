# Native x86_64 Linux baseline experiment

This is a review draft for `s3loy/cli-release-kit-acceptance`, prepared on
2026-11-17. Native builds and runtime checks have not run under this draft.
The experiment asks whether the selected current toolchains and applications
can retain a GNU/glibc 2.17 baseline. Failures keep that candidate and their
original evidence for diagnosis.

The workflow is [linux-baseline.yml](../../.github/workflows/linux-baseline.yml).
Its proposed branch is `acceptance/linux-baseline-20261117`, based on
`c0c8d70f28c3225b2a5b90474c8e22d6053c898b`. Only that branch triggers it.
Preparing this draft does not commit, push, start Actions or publish a Release.

## Execution and cases

An Ubuntu 24.04 GitHub-hosted x86_64 VM orchestrates pinned build and runtime
containers. Both the host and Docker daemon must report x86_64. Local ARM64
execution and QEMU are excluded. The hosted VM image can change; its actual
image version, Python identity, architecture and kernel are recorded. Compilers
for the applications come from the pinned inputs below.

The workflow runs preparation, rejection controls, then five independent
language jobs with `fail-fast: false` and `max-parallel: 2`. Every language case
builds once, creates a tar.gz, independently extracts it, checks payload identity
and runs the extracted executable in all three clean runtime userspaces.

| Required role | Frozen subject | Required observations |
| --- | --- | --- |
| `controls` | Prior relship ELF requiring glibc 2.39; generated incompatible shared-library fixture | Reject high ABI and missing SONAME, observe actual loader failures on old userspaces, accept the controls on the new userspace |
| `rust-engine` | Same relship production source as the prior hosted comparison | SDK bootstrap, native dependencies, ELF inspection, bare `--version`/`build-info`/`targets`, then retained collection `status` and offline `verify` |
| `rust-default` | ripgrep 15.2.0, original release profile | Original ten functional assertions in each userspace |
| `rust-pcre2` | Same ripgrep plus locked bundled PCRE2 | Ten original assertions, PCRE2 version and lookbehind, evidence that bundled C objects and static archive were linked |
| `go` | GoAWK 1.30.1, pure Go | `CGO_ENABLED=0`, `GOAMD64=v1`, no unexpected ELF interpreter/shared dependency, original four assertions |
| `c` | curl 8.23.0 with source-built OpenSSL 3.5.9 | CMake File API executable selection, static OpenSSL closure, twelve local HTTP/TLS assertions, including verification failures |

The engine reader check uses the old build image with its declared Git binary.
Its retained collection contains macOS ripgrep payload bytes for offline
verification; that payload is never executed by the Linux reader check. Clean
engine runtime checks and the Git-equipped reader check have separate reports.

C builds use an isolated manual CMake recipe. A successful experiment would
establish feasibility for these bytes and checks; relship's product CMake
integration remains separate work.

The curl recipe fixes a specific HTTP/TLS feature set before execution: static
OpenSSL remains enabled; HTTP/2, HTTP/3, SSH, LDAP, GSSAPI, IDN, libpsl and
optional compression dependencies are disabled. TLS tests pass an explicit
local CA with `--cacert`; the recipe does not bundle a general system CA store.
These choices stay identical in all three userspaces. Passing would not
qualify a full-featured curl distribution or general public HTTPS trust setup.

## Fixed inputs

All build and runtime references are platform manifest digests for
`linux/amd64`. [image-pins.json](image-pins.json) retains full manifest and
config digests. The controller checks Docker's pulled config ID and observes
the expected libc before any application build.

| Use | Image | Selected manifest digest |
| --- | --- | --- |
| Build | PyPA manylinux2014 x86_64 | `sha256:e6a785657009c612fe2a85fa933051d03a50ba62b1c5e47d62abcab546a2e423` |
| Clean glibc 2.17 | CentOS 7 | `sha256:dead07b4d8ed7e29e98de0f4504d87e8880d4347859d839686a31da35a3b532f` |
| Clean glibc 2.31 | Ubuntu 20.04 | `sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a` |
| Clean glibc 2.39 | Ubuntu 24.04 | `sha256:77eb101c607d6e3d4f5ad0c8a02c2136c689b98aba1f359e6502ba517e5c57ec` |

CentOS 7 is an old compatibility probe. It is not a supported production-OS
recommendation. Runtime containers receive the extracted program and test
inputs, without installing compilers, Git or a replacement libc.

| Input | Pin and verification |
| --- | --- |
| relship source | Source ID `776378e8a5d4d2dd0bef41985f753415de6d2a8b637044f00ddc52f5608b30ff`; production-file hashes and unchanged Cargo.lock |
| Rust | 1.96.0; official manifest and rustc/cargo/rust-std archive SHA256; 147 installed SDK file identities |
| ripgrep | 15.2.0, upstream `e89fff89ac9af12e8d4ce9d5fd07beb408ca730f`; source archive, Cargo files and 49 registry checksums |
| Go | 1.27.4 Linux amd64 archive SHA256, checked against official Go download metadata |
| GoAWK | 1.30.1, upstream `fa6df5c3ff1e6532e76faa6c756784836731f4e4`; archive SHA256 and 25-file allowlist; no external modules |
| CMake | 3.31.12 Linux x86_64 archive SHA256 and signed checksum |
| curl | 8.23.0 official tar.xz SHA256 and detached signature |
| OpenSSL | 3.5.9 official archive SHA256 and detached signature; built inside the selected baseline |
| C compiler, linker, Make, Perl and ELF tools | Fixed by the build image digest; actual paths, versions and package inventories retained |

Exact URLs, hashes, source inventories and signature fingerprints are in
[Rust/ripgrep pins](ripgrep/harness/input-pins.json),
[engine pins](r-old/harness/input-pins.json),
[Go pins](g-pure/harness/input-pins.json) and
[C pins](c-native/inputs.json). Cargo fetch runs with the exact SDK and locked
source on the native host; compilation is offline. Native libraries are built
from the frozen source inputs in the old build environment. Go module access
is disabled. Input mismatches stop the affected role.

The build image's exact `LD_LIBRARY_PATH` and `PKG_CONFIG_PATH` values are
declared in the engine pins. Other unrequested Cargo/profile overrides fail.
No case changes the original ripgrep profile or silently substitutes a newer
baseline, disables curl TLS, enables CGO or removes assertions.

## Rejection controls and retained fixtures

[high-control.json](high-control.json) binds the prior Ubuntu 24.04 relship
binary to its original run, artifact SHA256, source ID and executable SHA256.
Its exact bytes are retained as `controls/known-high-relship.gz` (5,405,146
bytes). Both compressed and uncompressed hashes are checked. Execution does
not fetch the original expiring Actions artifact or require an Actions API
token.

The second control compiles a main program in the old image and links a bundled
shared library to the selected new libc's `strlcpy`. It requires the main
program's own version needs to fit 2.17 while the library exceeds 2.17. The
prototype must reject the closure, the old loaders must reject it, and the new
loader must run it. Removing the shared library must produce a missing-SONAME
failure. Control-construction failure blocks the language jobs and retains its
evidence.

The engine reader fixture is 6,161,724 bytes, pinned at
`3cd5fec0470762bb01794c085dab3c872dd9a5acf24a1a99aedc4d7b1f41c25a`.
It contains a collection, public verification policy, source overlay Git
bundle and status receipt, with 32 archive files. Three original text records
retain `/Users/s3loy/workshop/project/cli-release-kit/...` paths and invocation
metadata. Those bytes remain unchanged so the signed collection can be checked.
The fixture has no private signing key or GitHub token. The two compressed
fixtures total about 11.03 MiB and would be included in the proposed branch.

## Bounds, evidence and failure handling

Build containers have two CPUs, 2 GiB RAM, a process limit, a read-only root,
explicit writable output mounts and no network. Functional tests use host-side
Python and clean containers. Curl alone uses host networking to reach its
loopback HTTP/TLS fixture; the fixture is locally generated. No Docker socket,
checkout credentials or entire historical consumer directory enters a guest.

| Role | Shared controller budget | Actions step | Whole job |
| --- | ---: | ---: | ---: |
| Rejection controls | 40 minutes | 45 minutes | 50 minutes |
| Each language case | 80 minutes | 85 minutes | 90 minutes |

Individual builds are capped at 40 minutes. Preparation, pulls, builds and
checks share the controller deadline; their individual caps are not additive
reservations. The Actions limits leave room for bounded cleanup and report
upload. These are proposed ceilings, not measured build times. Hosted-runner
termination or an unavailable Docker daemon can still prevent complete logs;
missing results fail the final summary.

Owned containers share an experiment label. Cleanup has a separate bounded
budget, reports failures and preserves an earlier build/check error. Job and
engine summaries remain failed after initialization, fixture or cleanup
failures. Report collection failures also change the job result to failed.

Artifacts retain reports and logs for three days. They include input-fetch and
signature reports, original command output, ELF version/dynamic inspection,
package identities, functional assertions and safe fixture response headers.
Source trees, SDKs, caches, executables, package archives and TLS private keys
are excluded. Six required job results must each appear exactly once and
agree on the baseline and experiment scope. Missing, duplicate, malformed or
failed results reject the summary. Actions are pinned to full commit SHAs;
the workflow requests only `contents: read` and disables persisted checkout
credentials.

If a tool will not start, an ELF requirement is too new or an assertion fails,
the role fails with its original inputs. There is no automatic baseline
increase or replacement build. The next step is to locate the failing tool,
native dependency, linker or application behavior before choosing another
recipe with s3.

## Review and verification boundary

On any host, static checking is available without starting Docker:

```sh
python3 compatibility/baseline/run.py check
actionlint .github/workflows/linux-baseline.yml
```

The draft has received static checks, retained-input hash checks and controlled
host-side failure-path checks. It has not received native Linux build, ELF,
runtime or package acceptance under this workflow. Containers share the
Ubuntu runner kernel and CPU; passing does not qualify a minimum old kernel,
minimum CPU, every distribution or every application feature. This experiment
does not cover ARM, musl or native package-manager installation.

Only `.github/workflows/linux-baseline.yml` and `compatibility/baseline/**` are
proposed additions to the isolated acceptance branch. Product code remains
unchanged. No staging, commit, push, tag or Release is part of preparing this
review draft.

Workflow semantics follow GitHub's
[matrix controls](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/run-job-variations),
[timeouts](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax),
[full-SHA action references](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/find-and-customize-actions)
and [artifact retention](https://docs.github.com/en/actions/tutorials/store-and-share-data).
