# RosaryEDR

A Windows-only, x86_64 Rust binary project for defensive security research and
authorized malware analysis. The executable uses `windows-sys` to monitor new
process starts through Event Tracing for Windows (ETW).

## Prerequisites

- Windows 10 or later on x64.
- Stable Rust installed through [rustup](https://rust-lang.org/tools/install/).
- Visual Studio or Visual Studio Build Tools with **Desktop development with C++**,
  including the MSVC x64 build tools and a Windows 10 or Windows 11 SDK. See the
  [official Windows setup guide](https://rust-lang.github.io/rustup/installation/windows-msvc.html).

`rust-toolchain.toml` selects the stable Windows x64 MSVC toolchain.
`.cargo/config.toml` makes `x86_64-pc-windows-msvc` the default build target.

## Build and run

Run these commands in an Administrator PowerShell from the project directory.
The account must be permitted to start ETW sessions and enable the process provider.

```powershell
rustup update stable --no-self-update
cargo build
cargo run
```

The executable listens until Ctrl+C or Ctrl+Break. Start another application while
it is listening to see events like:

```text
Process started: PID=1234 ParentPID=5678 Image=\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe
```

Image paths are printed with escaped backslashes and control characters. The image
path is the provider's value, which may use Windows device paths.
The debug executable is `target\x86_64-pc-windows-msvc\debug\rosaryedr.exe`.

For an optimized build:

```powershell
cargo build --release
cargo run --release
```

The release executable is `target\x86_64-pc-windows-msvc\release\rosaryedr.exe`.

## Verify

```powershell
cargo test
cargo clippy --all-targets -- -D warnings
```

The tests exercise Windows' TDH decoder with version-zero and version-one
process-start payloads, a header PID that differs from the new process PID, Unicode
image names, and missing/truncated payloads. Error handler tests verify suppression,
cause reporting, retained native codes, distinct NTSTATUS descriptions for statuses
that share a Win32 mapping, native catalog fallback, and last-error preservation.
Process telemetry tests collect all four native helper results from the current
process through `NtOpenProcess`, verify that owned records remain usable after
the handle closes and can be shared across threads, and preserve native failures
when query access is missing. Both full and limited query access are exercised.
PE address tests compare the current x64 image with `GetModuleHandleW`, exercise
pointer widths and access failures, and inspect a 32-bit Windows PowerShell child
that independently reports its image base. The child is launched without a window
and is stopped after the test.
Dynamic import tests verify the resolved native read signature and preserve the
Win32 failure returned for a missing export.
These tests do not require administrator permissions. The standalone process-handle
and telemetry components are compiled in test builds.
Live session capture requires the ETW permissions described above.

Source formatting follows the Allman-style braces required by `AGENTS.md`.

## ETW process-start monitoring

All monitoring logic is in `src/ETW/mod.rs`; `src/main.rs` starts it and returns a
failure exit code when startup fails. The module creates the `RosaryEDR-ProcessStart` real-time session,
enables `Microsoft-Windows-Kernel-Process` with process keyword `0x10`, and handles
only event ID 1 (ProcessStart). Existing processes are not enumerated.

PID, parent PID, and image name come from the event payload, decoded by Windows'
Trace Data Helper (TDH) using manifest field names. This handles event layout
differences between Windows versions without fixed byte offsets. Records and
payload pointers are borrowed only during the callback; decoded values are owned.

Ctrl+C closes the consumer and stops the owned session. Startup failures also
release acquired resources. A second monitor instance fails rather than attaching
to or stopping an existing session. ETW loss counters are reported on shutdown
when nonzero; high event rates or slow output can cause dropped events.

If the monitor is forcibly terminated, its session may remain active. After
confirming no monitor is still running, stop the orphaned session from an
Administrator PowerShell before restarting:

```powershell
logman stop RosaryEDR-ProcessStart -ets
```

The implementation uses Microsoft's documented
[ETW controller and consumer APIs](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
and [TDH property decoding](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty).

## Error handling

`src/ErrorHandle/mod.rs` provides shared native error handlers. Every handler takes
a `print_to_console: bool` parameter: `true` writes to stderr, and `false` produces
no console error output. Suppression preserves error values and failure exit codes.

```rust
let error = error_handle::handle_win32_error(status, "StartTraceW", true);
let error = error_handle::handle_last_error("OpenTraceW", false);
let _ = error_handle::handle_std_error(&error, "Opening the trace", true);
```

Call `handle_last_error` immediately after an API fails and only when that API
documents `GetLastError` as its error source. For APIs such as `StartTraceW` and
`TdhGetProperty` that return a status directly, use `handle_win32_error` with that
status. Both return `std::io::Error` with the original raw Win32 code.

For native system services that return NTSTATUS, `handle_ntstatus_error` takes the
returned status directly. It uses `RtlNtStatusToDosError` for I/O classification
while retaining the original status in
`NtStatusError`. Access it with `error.get_ref()` and
`downcast_ref::<error_handle::NtStatusError>()`; its fields are `status` and
`win32_code`. These errors have a typed payload rather than `raw_os_error()`.

`src/ErrorHandle/error_map.rs` maps all 39 stable `std::io::ErrorKind` variants in
Rust 1.99 to descriptions, with a fallback for unlisted or future categories.
Other types implementing `std::error::Error` use their own description and cause
chain. Error causes are limited to 16 levels to bound reporting.

The same map contains `NTSTATUS_DESCRIPTIONS`: 52 common process, memory, file,
security, wait, and exception statuses, using the constants supplied by
`windows-sys`. `ntstatus_details(status)` returns the symbolic name and description
for a listed status, or `None` when it is unlisted. Codes with aliases use a single
canonical name, such as `STATUS_SUCCESS` for zero. This is a focused map, not an
exhaustive list of every NTSTATUS defined by Windows.

Native error reporting uses the original NTSTATUS to select its name and
description, so different statuses remain distinguishable even when they map to
the same Win32 code. For example:

```text
NTSTATUS 0xC000000B (STATUS_INVALID_CID, Win32 87): The supplied process or thread identifier is invalid.
```

Unlisted statuses use `FormatMessageW` with the already-loaded `ntdll.dll` message
catalog; the original hexadecimal status and mapped Win32 code are still shown.
If that catalog has no description, reporting uses a numeric NTSTATUS fallback.
Status lookup follows Microsoft's
[NTSTATUS reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)
and [module message lookup contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew).

Win32 code descriptions come from the native Windows system message catalog via
`FormatMessageW`, rather than a duplicate list of thousands of strings. The lookup
uses the system's language selection, ignores message inserts, frees its native
allocation, and preserves the calling thread's last-error value. Unknown or
application-defined codes retain their decimal/hex code with a fallback message.
Both native catalog lookups preserve the calling thread's last-error value.
System messages do not cover every module-specific or HRESULT value. NTSTATUS
conversion can return `ERROR_MR_MID_NOT_FOUND`; reporting still describes the
original NTSTATUS independently of that conversion.

`src/main.rs` calls `etw::monitor_process_starts(true)`. Pass `false` to suppress
ETW errors throughout startup, callbacks, and cleanup. Process-start events still
print normally. Console reporting is best effort; `handle_std_error` returns any
console write failure without replacing the original error being reported.

## Process directives

`src/ProcessDirectives/handle.rs` is a standalone process-handle component.
It is included only in test builds for verification and has not been wired into
the ETW event flow. The folder also contains `Telementry/Generic/helpers.rs` for
native metadata queries and `Telementry/Generic/data.rs` for owned data collection;
`Telementry/PE/helpers.rs` provides main executable image-address discovery.
`imports.rs` centralizes additional dynamically resolved process/token APIs.
The spelling `Telementry` is intentional.

Its API is `open_process(process_id, desired_access, print_errors)`, returning
`std::io::Result<std::os::windows::io::OwnedHandle>`. The access argument is a
`windows-sys` `PROCESS_ACCESS_RIGHTS` mask. Choose the rights required for the
planned operation, such as:

| Operation | Requested rights |
| --- | --- |
| Basic process metadata | `PROCESS_QUERY_LIMITED_INFORMATION` |
| Reading process memory | `PROCESS_VM_READ` |
| Memory inspection with process queries | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ` |

Windows checks the requested rights against the process's security restrictions.
A PID is opened through the `windows-sys` binding to `ntdll!NtOpenProcess`, the
user-mode entry point for the native system service. The call uses a correctly
sized `OBJECT_ATTRIBUTES` with no object name or inheritance flag and a
`CLIENT_ID` containing the PID. Nonnegative NTSTATUS values indicate success.
A successful open returns a real, non-inheritable process handle. `OwnedHandle`
closes it automatically when dropped; its standard `AsHandle`/`AsRawHandle` traits
support borrowing it for native calls while the owner remains alive.

An empty access mask returns `InvalidInput`. Native failures use the returned
NTSTATUS, with PID/access context, and retain both the original status and its
equivalent Win32 code through the shared error system.
`print_errors` controls reporting through `ErrorHandle`, including suppressed
failures that still return `Err`.

The implementation follows the native
[NtOpenProcess access contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess)
and Rust's [OwnedHandle ownership model](https://doc.rust-lang.org/std/os/windows/io/struct.OwnedHandle.html).

### Dynamic process and token API imports

`src/ProcessDirectives/imports.rs` provides
`process_apis(print_errors) -> io::Result<&'static ProcessApis>`. It resolves the
fixed `NtReadVirtualMemory` export from the already-loaded `ntdll.dll` through
`GetProcAddress` and casts it only to its matching typed native signature.
`ProcessApis::nt_read_virtual_memory` is the resulting unsafe function pointer.
The PE helper uses this table instead of a direct native declaration.

`GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN)` keeps the module loaded for
the calling process's lifetime. `OnceLock` caches either the complete API table
or its original Win32 loader failure, with thread-safe initialization. Each caller
chooses whether a cached failure prints through `ErrorHandle`; errors are still
returned when printing is suppressed.

This module is restricted to APIs required by process/token workflows. Its public
interface accepts no arbitrary DLL or export names. Extend it with an exact typed
signature and fixed export lookup when another API is needed. Bindings already
available through `windows-sys` continue to be used directly. The loader is
currently included in test builds with the other standalone process components.

The implementation follows the Windows
[export lookup contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
and [module lifetime contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw).

### Process telemetry

See the [telemetry README](src/ProcessDirectives/Telementry/README.md) for helper
purpose, field definitions, access requirements, and current-process usage examples.

`src/ProcessDirectives/Telementry/Generic/helpers.rs` provides four independent queries.
Each takes `BorrowedHandle<'_>` and `print_errors: bool`, returns an
`std::io::Result`, and reports failures through the shared NTSTATUS error system.
The helpers borrow the handle without closing it or transferring ownership.
They are compiled and exercised in test builds, alongside the process-handle
component, and have not been wired into the runtime ETW event flow.

`src/ProcessDirectives/Telementry/Generic/data.rs` is the generic telemetry entry
point. Its `collect_process_data(handle, print_errors)` calls all four helpers and
returns `io::Result<ProcessData>`. The owned record contains `ObjectData`,
`ProcessBasicData`, `ProcessProtection`, and `Vec<String>` enabled privileges.
Native-width identifiers and the PEB address are stored as `usize`; exit status,
access rights, attributes, counts, and reserved object values are preserved.
The record contains no handles or borrowed data and can be retained in collections
or shared across threads after the source handle closes. Collection stops at the
first failed query, preserving its error without returning a partial record.

| Helper | Native query | Returned information |
| --- | --- | --- |
| `query_object_basic_information` | `NtQueryObject(ObjectBasicInformation)` | `PUBLIC_OBJECT_BASIC_INFORMATION`: attributes, granted access, handle count, pointer count |
| `query_process_basic_information` | `NtQueryInformationProcess(ProcessBasicInformation)` | `PROCESS_BASIC_INFORMATION`: exit status, PEB address, affinity, base priority, PID, parent PID |
| `query_process_protection` | `NtQueryInformationProcess(ProcessProtectionInformation)` | `ProcessProtection`: raw level byte and decoded protection type, audit flag, signer |
| `query_enabled_process_privileges` | `NtOpenProcessToken(TOKEN_QUERY)` and `NtQueryInformationToken(TokenPrivileges)` | `Vec<String>` containing enabled privilege names |

The existing `windows-sys` structures supply the native object and process layouts.
Object basic information's `HandleCount` counts open handles referring to that
object across the system, and `PointerCount` counts kernel references to it.
Neither counts the handles owned by the target process. `GrantedAccess` is the
access mask on the particular handle being queried. Object queries accept other
object types too, so object information alone does not establish process identity.
The reserved object fields are returned but are not interpreted.

Process basic and protection queries need process query access. Use
`PROCESS_QUERY_LIMITED_INFORMATION` or `PROCESS_QUERY_INFORMATION` when opening
the process. A successful basic query identifies the process through
`UniqueProcessId`; its `PebBaseAddress` is a native address in the target process.
The helper does not dereference that address locally or read PEB contents.

`PS_PROTECTION` is queried as one byte. Its low three bits are `protection_type`,
bit three is `audit`, and the high four bits are `signer`. The decoded snapshot
preserves the raw `level` and numeric fields, including unrecognized values.
Protection types are 0 (none), 1 (protected light/PPL), and 2 (fully protected).
Known signer categories are 0 (none), 1 (Authenticode), 2 (CodeGen), 3 (Antimalware),
4 (Lsa), 5 (Windows), 6 (WinTcb), 7 (WinSystem), and 8 (App). The signer field is an
OS protection category, rather than a file-signature verification result.

The privilege helper opens the process's primary token with `TOKEN_QUERY` and
returns only privileges carrying `SE_PRIVILEGE_ENABLED`, excluding removed entries.
Default-enabled or previously-used flags alone do not establish current enabled
state. It validates the variable-length native buffer, resolves LUID names with
`LookupPrivilegeNameW`, and closes the owned token handle on every return path.
An empty enabled set returns an empty list; lookup failures return `Err`.
Use `PROCESS_QUERY_INFORMATION` for the documented native token-open contract;
tests also verify limited query access on the current Windows system.

The helpers validate returned buffer lengths and return `InvalidData` for
unexpected layouts. Native failures retain their original NTSTATUS and mapped
Win32 code. `print_errors = false` suppresses reporting while still returning
`Err`. Successful queries return data without console output. Values are snapshots;
counts and process state can change between calls.

The implementation follows Microsoft's
[object basic-information contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject)
and [process basic-information contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).
The protection layout comes from the
[phnt native headers](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h), also
documented by the supplied [PS_PROTECTION reference](https://ntdoc.m417z.com/ps_protection).

### Main executable image address

`src/ProcessDirectives/Telementry/PE/helpers.rs` exposes
`query_process_pe_address(handle, print_errors) -> io::Result<ProcessPeAddress>`.
The owned result contains `peb_base_address`, `image_base_address`, and `is_wow64`.
The image address is the main executable's mapped base, as reported by its PEB.

The x64 caller queries `ProcessWow64Information` (class 26). A nonzero result
selects the target's PEB32; otherwise it reuses the generic
`ProcessBasicInformation` helper for the native PEB. It reads only the selected
PEB's `ImageBaseAddress` field through `NtReadVirtualMemory`: four bytes at offset
`0x08` for WoW64, or eight bytes at offset `0x10` for native x64. Returned lengths,
address arithmetic, and nonzero addresses are checked; failures use `ErrorHandle`.

Before returning the address, it calls
`validate_process_pe_image(handle, image_base_address, print_errors) -> io::Result<usize>`.
This helper reads a fixed 64-byte DOS header, checks `MZ`, decodes signed
`e_lfanew` at offset `0x3C`, rejects negative or overlapping offsets, and reads
four bytes at `image_base_address + e_lfanew` to check `PE\0\0`.
Every read range is checked for address overflow and exact transfer length;
no allocation depends on the target's offset. The standalone helper returns the
numeric NT signature address. Invalid signatures/offsets return `InvalidData`,
and native read failures retain their NTSTATUS through `ErrorHandle`.

Request `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, or limited query access
plus `PROCESS_VM_READ`. The project is x64-only, so a 32-bit caller's
`NtWow64QueryInformationProcess64` path is outside the configured target.
The helper is compiled in test builds and remains separate from the generic data
collector and runtime ETW flow. It returns numeric addresses without dereferencing
remote pointers in Rust. Matching signatures do not establish a genuine mapped
image or validate its remaining headers. The PEB and image memory are
target-writable and can change between reads; future entry-point and section
parsing must validate its own lengths, offsets, and RVAs.

`windows-sys` 0.61.2 supplies the query bindings and native types. Its bindings
omit `NtReadVirtualMemory`; `ProcessDirectives/imports.rs` resolves the existing
`ntdll.dll` export and supplies its matching x64 function-pointer type without
another dependency.

The implementation uses the
[process-query contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess),
[PEB field layout](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm),
[Windows 11 x64 layout](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB),
[native read ABI](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h),
and [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

### Process COFF file header

`query_process_image_file_header(handle, image_base_address, print_errors)` in
`PE/helpers.rs` returns `io::Result<IMAGE_FILE_HEADER>` using the native
`windows-sys` type. It rechecks MZ/PE signatures, then reads the complete 20-byte
COFF header immediately after the NT signature through `NtReadVirtualMemory`.
The returned value owns all seven fields and can outlive the process handle.

Basic field checks require an x86 or x64 machine type, 1–96 sections,
`IMAGE_FILE_EXECUTABLE_IMAGE`, and a declared optional-header size of at least
96 bytes for x86 or 112 bytes for x64. DLLs with the executable-image flag are
accepted. The optional-header size remains variable; the helper does not require
exactly 224 or 240 bytes. Other COFF metadata is preserved without interpretation.

The standalone helper needs `PROCESS_VM_READ`; PEB-based address discovery also
needs process query access. Invalid signatures/fields/ranges return `InvalidData`,
and native read failures retain their NTSTATUS through `ErrorHandle`.
These are COFF consistency checks. Optional-header magic, image extents, data
directories, and section entries still require their own validation.
See the [usage guide](src/ProcessDirectives/Telementry/README.md#coff-file-header)
and Microsoft's [file-header definition](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header).

### Process optional-header layout

`query_process_image_optional_header(handle, image_base_address, print_errors)`
returns `io::Result<ProcessOptionalHeader>` with owned `magic`, `size_of_image`,
`size_of_headers`, and `section_alignment` values. It shares the validated COFF
reader with the file-header helper, using one DOS/PE validation per call.

The COFF guard checks `SizeOfOptionalHeader` against the machine's fixed-field
minimum. The helper then reads only the 64-byte prefix containing the requested
values through `NtReadVirtualMemory`. It requires PE32 magic `0x10B` for x86 or
PE32+ magic `0x20B` for x64, checks nonzero sizes/alignment, requires headers to
fit inside the declared image, checks that image size is a multiple of section
alignment, and requires the full declared optional-header extent to fit inside
`SizeOfHeaders`. Address arithmetic is checked without allocating from target sizes.

The result is a compact Rust record rather than a full native optional header.
It does not collect data directories or sections or establish actual mapped-memory
extents. `PROCESS_VM_READ` and the existing `ErrorHandle` boolean policy apply.
See the [optional-header usage guide](src/ProcessDirectives/Telementry/README.md#optional-header-layout)
and [Microsoft's format definition](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only).

### Process section addresses

[`PE/sections.rs`](src/ProcessDirectives/Telementry/PE/sections.rs) exposes
`query_process_sections(handle, image_base_address, print_errors) -> io::Result<Vec<ProcessSection>>`.
Its private `validate_image_headers` method delegates DOS/PE, COFF, and optional-header
checks to the shared helpers and returns a private `ValidatedImage` snapshot.
The collector uses the checked base and headers only after validation succeeds,
then reads the complete section table in one bounded native call. The table is
located after the declared optional header and must fit inside `SizeOfHeaders`.
The existing 1–96 section limit bounds its read buffer to 3,840 bytes. Header
validation runs once per collection and forwards the same boolean error policy.

Each owned record retains its raw eight-byte name, RVA, virtual size, raw size
and file offset, and characteristics. `address` is `image_base_address + RVA`;
`size` is the declared span `max(VirtualSize, SizeOfRawData)`, including raw padding
or the raw-size fallback when virtual size is zero. Section RVAs must match
`SectionAlignment`, and each declared span must fit inside `SizeOfImage`.
The first failure returns `Err` without a partial list, using `ErrorHandle`.

Pass `address` to the native memory reader while the process handle remains open.
The collector returns metadata without reading section contents. Empty sections
retain a zero span. Addresses and characteristics do not establish current page
readability or protection. The component is exposed as `process_pe_tests::sections`
in test builds and remains separate from the runtime ETW flow.
The [usage guide](src/ProcessDirectives/Telementry/README.md#usage-access-a-section)
shows section lookup and a bounded memory read. Layouts follow Microsoft's
[section-table specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-table-section-headers).

### Byte signatures in memory-read results

[`src/ProcessDirectives/Telementry/PE/signatures.rs`](src/ProcessDirectives/Telementry/PE/signatures.rs)
contains labeled `MZ_SIGNATURE`, `PE_SIGNATURE`, `X64_NOP`, `X64_RET`, and
`X64_INT3` arrays. Developers can add another documented `pub const NAME: [u8; N]`
and pass it directly to `contains_signature(read_bytes: &[u8], signature: &[u8]) -> bool`.

The helper searches for an exact contiguous match anywhere in the supplied
slice using Rust's [slice windows](https://doc.rust-lang.org/std/primitive.slice.html#method.windows),
without allocating or calling a memory API. Empty patterns, insufficient data,
and absent patterns return `false`. All bytes are literal, including `0x00`;
there are no wildcards or instruction decoding.

After a successful `NtReadVirtualMemory` or `ReadProcessMemory`, call
`contains_signature(&buffer[..bytes_read], &PE_SIGNATURE)` with only the bytes
actually transferred. A failed read remains an error handled by the caller.
The PE helper exposes the module as `process_pe_tests::signatures` in the current
test-build setup and reuses its MZ/PE arrays at the required header positions.
See the [telemetry usage guide](src/ProcessDirectives/Telementry/README.md#byte-signature-matching)
for a native-read example and adding custom signatures.

## Dependencies and updates

The Windows API crate is
[`windows-sys` 0.61.2](https://docs.rs/windows-sys/0.61.2/windows_sys/).
The enabled features are `Wdk_Foundation`, `Wdk_Storage_FileSystem`, `Wdk_System_Threading`,
`Win32_Foundation`, `Win32_Security`, `Win32_System_Console`,
`Win32_System_Diagnostics_Debug`, `Win32_System_Diagnostics_Etw`,
`Win32_System_Kernel`, `Win32_System_LibraryLoader`, `Win32_System_SystemInformation`,
`Win32_System_Threading`, `Win32_System_Time`, and
`Win32_System_WindowsProgramming`. The WDK namespaces provide the native API
bindings used here, including token APIs in `Wdk_Storage_FileSystem`;
`Win32_System_Kernel` enables the native PEB/process-information
types. `Win32_System_SystemInformation` enables the native machine constants
and `IMAGE_FILE_HEADER` binding; the binary remains a user-mode Windows application.
Add API features to `Cargo.toml` as the project needs them.

The minimum compiler version is Rust 1.87 because the error map includes the stable
`InvalidFilename` category. The project toolchain continues to select latest stable.

The stable channel follows stable releases when `rustup update stable` is run; it
does not update an already installed toolchain on every build. `Cargo.lock` records
resolved dependency versions and should be committed with the binary project.
`target/` contains generated build artifacts and is ignored.
