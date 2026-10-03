# DDS KLayout integration

[Official integration guide](https://docs.altifigence.com/products/digital-design-studio/plugins/) · [한국어](https://docs.altifigence.com/ko-kr/products/digital-design-studio/plugins/) · [Build a DDS plugin](https://docs.altifigence.com/developers/plugin-sdk/) · [Releases](https://github.com/Altifigence/dds-klayout-plugin/releases)

The actual source of Digital Design Studio's optional **KLayout 0.30.12** viewer
integration, released under Apache-2.0. It installs a pinned official external
viewer in DDS-owned user storage and opens a saved GDSII/OASIS file through a
native picker. It does not qualify a layout producer, DRC/LVS flow or engine tool.

This is integration source, with a standalone package audit harness. KLayout
itself is a separate GPL-3.0-or-later application. Its source and notices are
available independently; this Git repository distributes no executable or icon.

## Source and build boundary

The 11 files in [source-inventory.json](source-inventory.json) are byte-for-byte
exports from the recorded DDS source commit:

- `src-tauri/src/native_klayout.rs`: actual Tauri commands, workspace/window/session
  authorization, install reservations, cancellation, staging, status and launch.
- `src-tauri/src/native_klayout_package.rs`: actual fixed descriptor selection,
  bounded download, SHA-256 validation and Windows ZIP extraction/audit, including
  its five original Rust tests.
- `src-tauri/src/native_klayout_linux.py`: actual Ubuntu/WSL helper, Debian archive
  validation, user storage, dependency/version/display checks and fixed launch.
- `scripts/klayout-linux-package.test.py`: four original synthetic package tests.
- The pinned descriptor, five KLayout-specific Tauri permission definitions and
  the TypeScript host/state wire contract, preserved at their DDS-relative paths.

`src/lib.rs` compiles the **same unmodified package module** using `#[path]`.
It exposes archive verification, pinned download and Windows payload audit and
extraction for other native hosts. `src/main.rs` is a read-only audit CLI.
The standalone dependency lock contains only public crates and does not include
DDS host dependencies. The full Tauri adapter remains an integration module;
compiling that adapter requires the host interfaces described below.

## Build and verify

Install Rust 1.91.1 with Cargo. Windows also needs the MSVC C/C++ build tools and
CMake for the Rust TLS dependency; Linux needs a C/C++ toolchain and CMake.
Python fixture tests require POSIX ownership and symlink semantics; use Python
3.12 on Linux or WSL. Nothing below installs or runs KLayout.

```sh
cargo test --locked
cargo run --locked -- descriptor
python scripts/verify-source.py
python scripts/klayout-linux-package.test.py
```

The original Rust tests cover traversal/Windows aliases, integrity of changed,
missing and added files, cancellation and stalled network futures. The Python
tests cover Debian archive hashes, file/link inventory, path/link escapes and
user-directory symlinks. CI uses public GitHub-hosted Ubuntu and Windows runners,
commit-pinned actions and the checked-in Cargo lock.

To compare the published integration bytes to a DDS checkout:

```sh
python scripts/verify-source.py --dds-root /path/to/dds
```

To audit an existing official archive without extracting or executing it:

```sh
cargo run --locked -- verify-archive windows-x86_64 /path/to/klayout-0.30.12-win64.zip
cargo run --locked -- verify-archive ubuntu24-x86_64 /path/to/klayout_0.30.12-1_amd64.deb
cargo run --locked -- verify-windows-payload /path/to/archive.zip /path/to/payload
```

## Integrate into a host

Use the Rust library's pinned archive/payload functions when adapting package
management. They operate on explicit caller-owned paths and an `AtomicBool`
cancellation flag. The Python helper implements the existing `inspect`, `stage`,
`commit`, `discard`, `uninstall` and `open` protocol. Its command-line arguments are
`action`, opaque UUID ticket, saved layout path (only for `open`) and the exact
JSON descriptor; `stage` reads exactly the pinned archive bytes from stdin.
It prints one bounded JSON status and returns a nonzero exit on a JSON error.
Run it with isolated Python (`python3 -I`) and a fixed command, as the adapter does.

The original Tauri module assumes these host-owned interfaces:

- `native_console::WorkspaceLease`: a retained workspace authority guard,
  `environment()` and, on Windows, selected `wsl()` workspace information.
- `native_console::Environment::OnPremises` and `request_session(request)`:
  native environment and authenticated renderer session identity.
- `desktop_runtime_security::sanitize_child_environment(command)`: child-process
  environment sanitization that must preserve the explicit fixed launch settings.
- On Windows, `desktop_wsl_backend::transport`: trusted system WSL command lookup,
  `WslProject::new` distribution validation and `WslProject::from_unc` path mapping.
- Tauri application-local storage, dialog plugin, main window and native async
  runtime. Register the five commands and permit their matching exported permission
  identifiers only on the intended window. Use the exported TypeScript wire contract.

These interfaces are responsibilities of the embedding host. Their DDS
implementations and the UI/catalog/application are outside this source export.
Do not remove the authorization, session binding, distribution validation or
environment sanitization when connecting the module to another host.

DDS uses Windows x64 app-local storage, or unprivileged Ubuntu 24.04 x64 storage
in the native-selected WSL distribution/Linux user account. Ubuntu dependencies
are recorded individually in the descriptor and must already be installed.
Cloud, other Linux releases and other architectures are unsupported. Linux GUI
launch requires a display or WSLg. Saved-layout launch uses fixed `-nc -rx -ne`
arguments; renderer-provided scripts, commands and environment are not accepted.

## Upstream source, dependencies and licenses

[upstream-source.json](upstream-source.json) records KLayout's immutable
`v0.30.12` commit `e71272c3b178105bd2a2f25af54673a7af7ed60d`, the official
corresponding source URL, exact measured 104,078,293-byte size and SHA-256.
Retrieve the unchanged source into ignored `dist/upstream/` with:

```sh
python scripts/fetch-upstream-source.py
```

The same verified archive can be attached to this integration's source release
as `klayout-0.30.12.tar.gz`. Its SHA-256 is
`fa747d9a4c216d0645587e05df365d5c22f73609ab98b34471372c711d8c2b75`.
This archive contains KLayout's build scripts and original dependency notices.
For the upstream application build, use its included `README.md`, `build.sh` or
`build.bat` and [official build instructions](https://www.klayout.de/build.html).
Its Windows build uses Qt, Ruby, Python, zlib, expat, curl and pthread-win; Linux
uses Qt with optional Ruby/Python support. Building that upstream application is
separate from building this integration harness.

Original GPL/MIT notices are retained under `licenses/source/` and the
commit-specific upstream GPL/COPYRIGHT files under `licenses/`.
[NOTICE](NOTICE) specifies the selected DDS-original Apache-2.0 grant.
The descriptor's original Windows and Ubuntu download URLs, SHA-256 and sizes
remain unchanged. [Windows notice inventory](upstream-windows-notices.json)
records the ZIP directory, DLL names and 66 filename-selected notice entries
obtained by bounded HTTPS ranges and validated with ZIP entry CRCs; this audit
does **not** verify the full Windows ZIP SHA-256. Some selected entries are
upstream license templates; selection by filename is not a declaration
that every bundled DLL has a complete notice/source set. The
[Ubuntu package audit](upstream-linux-notices.json) records the complete verified
archive hash, actual control/dependency fields and packaged copyright notice.
Neither audit installs or executes the application. These inventories document
their method and limits and do not replace upstream distributors' obligations.

Local synthetic checks establish integration package behavior and exported source
equality. They do not establish a clean-machine installation, installed GUI
acceptance, an upstream application build or DDS host/UI acceptance.
