# Error handling

[mod.rs](mod.rs) provides shared Rust, Win32, and NTSTATUS error reporting.
[error_map.rs](error_map.rs) contains the project's Rust I/O-kind descriptions
and focused NTSTATUS map. [src/main.rs](../main.rs) loads this folder as
`crate::error_handle`.

The module targets Windows x64 and uses the existing `windows-sys` dependency.
It writes diagnostics to stderr and returns errors for callers to propagate.

## Choosing a handler

| Error source | Function | Return value |
| --- | --- | --- |
| An existing Rust error implementing `std::error::Error` | `handle_std_error(&error, context, print_to_console)` | `io::Result<()>` describing only whether reporting succeeded. |
| A Win32 API's explicit error/status return | `handle_win32_error(code, context, print_to_console)` | `io::Error` retaining the raw Win32 code. |
| An API documented to report failure through `GetLastError` | `handle_last_error(context, print_to_console)` | `io::Error` retaining the captured last-error code. |
| A failed native NTSTATUS result | `handle_ntstatus_error(status, context, print_to_console)` | `io::Error` containing an `NtStatusError` payload. |
| A Win32 code whose description is needed without reporting | `win32_description(code)` | Owned `String` from the native catalog or a numeric fallback. |

The error handlers do not determine whether an operation failed. Check the API's
success contract first. For native queries in this project, callers treat
`status < 0` as failure before invoking `handle_ntstatus_error`.

For example, ETW's `StartTraceW` returns its status directly, so its failure uses
`handle_win32_error`. `OpenTraceW` uses a failure sentinel and `GetLastError`,
so its failure uses `handle_last_error`. See the [ETW implementation](../ETW/mod.rs).

Call `handle_last_error` immediately after detecting a failure that documents
`GetLastError` as its error source. Intervening API calls can overwrite the code.
Pass native NTSTATUS values directly to their handler rather than reading
`GetLastError`.

## Public API

```rust
pub fn handle_std_error(error: &(dyn std::error::Error + 'static), context: &str, print_to_console: bool) -> std::io::Result<()>
pub fn handle_win32_error(code: u32, context: &str, print_to_console: bool) -> std::io::Error
pub fn handle_last_error(context: &str, print_to_console: bool) -> std::io::Error
pub fn handle_ntstatus_error(status: NTSTATUS, context: &str, print_to_console: bool) -> std::io::Error
pub fn win32_description(code: u32) -> String
```

These are API signatures for reference. The `context` string labels the failed
operation in the printed diagnostic. It is not stored in the returned error.

### Reporting and propagation

For all four handlers, `print_to_console = true` enables stderr output and
`false` suppresses it. Suppression leaves error values and caller-controlled
failure results intact. Suppressed `handle_std_error` returns `Ok(())` without
formatting the error.

`handle_std_error` borrows the original error. Its return value describes the
console write, so callers must retain or return the original error separately.
For example, inside a function returning `std::io::Result<T>`:

```rust
use crate::error_handle;

let error = std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid process metadata");
let _ = error_handle::handle_std_error(&error, "Collecting process data", true);
return Err(error);
```

The Win32 and NTSTATUS handlers return the original constructed error even if
printing fails. They deliberately ignore the reporting result so a console
failure does not replace the operation failure. `win32_description` returns a
string and never prints it.

## Preserving native error information

### Win32 errors

`handle_win32_error` builds `io::Error::from_raw_os_error(code as i32)`.
The I/O error retains its raw Win32 code and Rust `ErrorKind` classification.
Codes with the high bit set retain their original 32-bit pattern through the
signed `raw_os_error()` representation; cast that value back to `u32` to inspect
the original unsigned code.

`handle_last_error` captures the thread's last-error value and passes it to the
same Win32 handler.

### NTSTATUS errors

`NtStatusError` implements `Debug`, `Display`, and `std::error::Error`:

| Public field | Type | Meaning |
| --- | --- | --- |
| `status` | `NTSTATUS` | Original native status supplied by the caller. |
| `win32_code` | `u32` | Corresponding code returned by `RtlNtStatusToDosError`. |

The handler uses the converted Win32 code to classify the enclosing
`io::Error`, then stores both codes in its typed payload. The enclosing error's
`raw_os_error()` is `None`; downcast its payload to retrieve the original status.

This self-contained example constructs and inspects an access-denied failure:

```rust
use crate::error_handle::{handle_ntstatus_error, NtStatusError};
use windows_sys::Win32::Foundation::STATUS_ACCESS_DENIED;

let error = handle_ntstatus_error(STATUS_ACCESS_DENIED, "Querying process information", false);
let native = error.get_ref().and_then(|cause| cause.downcast_ref::<NtStatusError>()).expect("The native handler stores NtStatusError");

assert_eq!(native.status, STATUS_ACCESS_DENIED);
assert_eq!(native.win32_code, 5);
assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
assert_eq!(error.raw_os_error(), None);
```

Status formatting uses the original NTSTATUS, so statuses that map to the same
Win32 code remain distinguishable. An unmapped conversion may return
`ERROR_MR_MID_NOT_FOUND`; the payload still retains the original status.
See Microsoft's [NTSTATUS conversion contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror).

## Description maps and native catalogs

The public `error_map` module exposes:

| Item | Type or signature | Purpose |
| --- | --- | --- |
| `IO_ERROR_DESCRIPTIONS` | `&[(ErrorKind, &str)]` | Current map of 39 Rust I/O error kinds to static descriptions. |
| `NTSTATUS_DESCRIPTIONS` | `&[(NTSTATUS, &str, &str)]` | Current map of 52 common statuses to symbolic names and descriptions. |
| `io_error_description` | `fn(ErrorKind) -> &'static str` | Looks up an I/O kind, with an unlisted-category fallback. |
| `ntstatus_details` | `fn(NTSTATUS) -> Option<(&'static str, &'static str)>` | Returns the mapped symbolic name and description, or `None`. |

The NTSTATUS map covers common process, memory, file, security, wait, and
exception statuses. It is a focused map, not an exhaustive status registry.
Aliases use one canonical entry, such as `STATUS_SUCCESS` for zero. The presence
of success or informational statuses in the map does not make them failures.

Mapped NTSTATUS values use the project's static description. Unlisted statuses
use `FormatMessageW` against the already-loaded `ntdll.dll` message catalog.
If that lookup fails, formatting retains the numeric status with a fallback
description.

Win32 descriptions use the Windows system message catalog instead of a duplicate
static map. Both catalog paths use the system's language selection, ignore
message inserts, trim the resulting text, and release the allocated native
buffer with `LocalFree`. The borrowed `ntdll.dll` handle is not freed.

These paths follow Microsoft's [FormatMessageW contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessagew).
The system catalog does not describe every module-specific, application-defined,
or HRESULT value. Failed lookups produce numeric fallbacks. Catalog lookup and
enabled standard-error reporting save and restore the calling thread's last-error
value.

## Diagnostic format

Reporting distinguishes Win32 errors, NTSTATUS errors, ordinary Rust I/O errors,
and other Rust errors. A native status is formatted like:

```text
NTSTATUS 0xC000000B (STATUS_INVALID_CID, Win32 87): The supplied process or thread identifier is invalid.
```

The complete diagnostic also includes the caller's context and an error category.
Win32 diagnostics include decimal and hexadecimal codes, an I/O category, and a
native system description.

The reporter follows `Error::source()` for at most 16 causes and prints a notice
when further causes remain. This bounds output even for cyclic cause chains.

## Verification

Run the existing tests from the project root:

```powershell
cargo test error_handle::tests
```

They cover suppressed formatting, last-error capture and preservation, original
NTSTATUS/code retention, distinct statuses sharing one Win32 conversion, native
catalog fallback, high-bit codes, Rust errors, cause chains, cyclic causes, and
console write failures. They do not require administrator permissions.
