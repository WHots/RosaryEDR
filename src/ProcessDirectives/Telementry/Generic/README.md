# Generic process telemetry

The Generic folder collects general metadata from an already-open Windows process.
[data.rs](data.rs) combines the queries in [helpers.rs](helpers.rs),
[handle_objects.rs](handle_objects.rs), and [window_objects.rs](window_objects.rs)
into one owned record. Call the individual
queries directly when only part of the metadata is needed.

This component targets Windows x64 and uses the project's existing
`windows-sys` 0.61.2 dependency. See the [telemetry README](../README.md) for the
related PE inspection components.

## Files and current integration

| File | Responsibility |
| --- | --- |
| [data.rs](data.rs) | Defines owned records and exposes `collect_process_data`. |
| [helpers.rs](helpers.rs) | Queries native object/process information, protection, enabled primary-token privileges, current directory, and full command line. |
| [handle_objects.rs](handle_objects.rs) | Owns handle snapshots, native object-type layouts, type-name resolution, and per-type counts. |
| [window_objects.rs](window_objects.rs) | Enumerates process-owned windows on the current desktop and returns window metadata, total HWND count, and invisible count. |

The declarations in [src/main.rs](../../../main.rs) currently load these files
only for test builds:

- `crate::process_telemetry_tests` loads `data.rs`.
- `crate::process_telemetry_tests::helpers` loads `helpers.rs`.
- `crate::process_telemetry_tests::handle_objects` loads `handle_objects.rs`.
- `crate::process_telemetry_tests::window_objects` loads `window_objects.rs`.
- `crate::process_handle_tests` loads [handle.rs](../../handle.rs) and provides `open_process`.
- `crate::process_imports` loads [imports.rs](../../imports.rs) and supplies `NtReadVirtualMemory`.

The runtime starts the ETW process monitor. Generic telemetry is not yet called
from process-start callbacks.

## Collect a complete record

```rust
pub fn collect_process_data(handle: BorrowedHandle<'_>, print_errors: bool) -> std::io::Result<ProcessData>
```

The collector runs these queries in order:

1. `query_object_basic_information`.
2. `query_process_basic_information`.
3. `query_process_protection`.
4. `query_enabled_process_privileges`.
5. `query_process_handle_type_counts`.
6. `query_process_parameters`.
7. `query_process_windows`.

It returns the first error unchanged. A failure produces no partial record or
default values. Use individual helpers if the caller needs to handle each query's
failure separately.
Handle-type counts are stored in `ProcessData::handle_type_counts`. Complete
collection requires `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.

### ProcessData

| Field | Type | Contents |
| --- | --- | --- |
| `object` | `ObjectData` | Handle attributes, granted access, and object reference counts. |
| `process` | `ProcessBasicData` | Process status, native PEB address, affinity, priority, PID, and parent PID. |
| `protection` | `ProcessProtection` | Raw protection byte and decoded fields. |
| `enabled_privileges` | `Vec<String>` | Names of currently enabled primary-token privileges. |
| `handle_type_counts` | `BTreeMap<String, usize>` | Counts of handles owned by the process, keyed by native type name such as `File`, `Process`, `Thread`, or `Event`. |
| `current_directory` | `PathBuf` | Current working directory read from the selected target process parameters. |
| `command_line` | `OsString` | Full command-line text, including the executable and its arguments. |
| `window_objects` | `ProcessWindowData` | Process-owned windows observed on the current desktop, total window-handle count, and invisible count. |

The record owns its data and contains no owned handles or borrowed pointers.
Window handles are retained only as numeric snapshot values. It supports
`Debug`, `Clone`, `PartialEq`, and `Eq`, can outlive the source handle, and can
be moved or shared across threads.

### ObjectData

| Field | Type | Meaning |
| --- | --- | --- |
| `attributes` | `u32` | Native attributes associated with the queried handle. |
| `granted_access` | `PROCESS_ACCESS_RIGHTS` | Access mask actually granted to this handle. |
| `handle_count` | `u32` | Number of open handles referring to the object across the system. |
| `pointer_count` | `u32` | Number of kernel references to the object. |
| `reserved` | `[u32; 10]` | Native reserved values, preserved without interpretation. |

The counts describe references to the object; they do not count handles owned by
the target process. An object query can also accept other object types, so success
alone does not establish that the supplied handle refers to a process.
See Microsoft's [object-information contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject).

### ProcessBasicData

| Field | Type | Meaning |
| --- | --- | --- |
| `exit_status` | `NTSTATUS` | Native process exit status. |
| `peb_base_address` | `usize` | Numeric native PEB address in the target's address space. |
| `affinity_mask` | `usize` | Process affinity mask reported by the native query. |
| `base_priority` | `i32` | Process base priority. |
| `process_id` | `usize` | Identifier of the queried process. |
| `parent_process_id` | `usize` | Parent process identifier reported by the native query. |

Identifiers, affinity, and addresses retain their native width. This field is
the native PEB address: the basic-information helper does not read PEB contents
or select a WoW64 PEB32. The parameter helper separately selects the appropriate
PEB for its reads. Use the [PE helpers](../PE/helpers.rs) for image-address
discovery. Do not dereference a remote address in the caller's address space.
See Microsoft's [process-information contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).

### ProcessProtection

`ProcessProtection` is defined in `helpers.rs` and re-exported by `data.rs`.

| Field | Type | Meaning |
| --- | --- | --- |
| `level` | `u8` | Original native protection byte. |
| `protection_type` | `u8` | Low three bits: `level & 0x07`. |
| `audit` | `bool` | Whether bit three is set: `level & 0x08 != 0`. |
| `signer` | `u8` | High four bits: `level >> 4`. |

The raw byte and numeric categories are preserved without rejecting unknown
values. The signer category describes OS process protection; the helper does not
verify the executable's file signature.

## Individual helpers

Every helper accepts `handle: BorrowedHandle<'_>` and `print_errors: bool`.
Metadata and parameter queries live in `helpers.rs`; handle-type counting lives
in `handle_objects.rs`; window enumeration lives in `window_objects.rs`.

| Helper | Return type | Native operation |
| --- | --- | --- |
| `query_object_basic_information` | `io::Result<PUBLIC_OBJECT_BASIC_INFORMATION>` | `NtQueryObject(ObjectBasicInformation)` |
| `query_process_basic_information` | `io::Result<PROCESS_BASIC_INFORMATION>` | `NtQueryInformationProcess(ProcessBasicInformation)` |
| `query_process_protection` | `io::Result<ProcessProtection>` | `NtQueryInformationProcess(ProcessProtectionInformation)` |
| `query_enabled_process_privileges` | `io::Result<Vec<String>>` | `NtOpenProcessToken(TOKEN_QUERY)` followed by `NtQueryInformationToken(TokenPrivileges)` |
| `handle_objects::query_process_handle_type_counts` | `io::Result<BTreeMap<String, usize>>` | `NtQueryInformationProcess(ProcessHandleInformation)` and `NtQueryObject(ObjectTypesInformation)` |
| `query_process_parameters` | `io::Result<ProcessParameters>` | Selects the native/WoW64 PEB with `NtQueryInformationProcess`, then reads parameter strings through `NtReadVirtualMemory`. |
| `window_objects::query_process_windows` | `io::Result<ProcessWindowData>` | `GetProcessId`, `EnumWindows`, `EnumChildWindows`, `FindWindowExW(HWND_MESSAGE)`, `GetWindowThreadProcessId`, and `IsWindowVisible`. |

The object and process helpers return the existing `windows-sys` structures.
Their native field names, such as `GrantedAccess`, `UniqueProcessId`, and
`PebBaseAddress`, become the corresponding snake_case fields in the owned record.
All three fixed-size queries validate the returned length before returning data.

### Enabled primary-token privileges

The privilege helper opens the process's primary token with `TOKEN_QUERY`.
It includes entries with `SE_PRIVILEGE_ENABLED` and excludes entries with
`SE_PRIVILEGE_REMOVED`. Default-enabled or previously-used flags alone do not
qualify an entry. See Microsoft's [privilege attributes](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges).

The helper validates the variable-length token buffer and privilege count before
reading entries. It uses an aligned `Vec<u32>` and makes at most three data-query
attempts when the required size grows. It resolves enabled privilege LUIDs into
local names with [LookupPrivilegeNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew),
such as `SeChangeNotifyPrivilege`.

Names are returned in native enumeration order. No enabled privileges produces
`Ok(Vec::new())`; any name lookup failure returns `Err` instead of an incomplete
list. The helper closes its separate token handle on every return path after
taking ownership. It queries existing state without changing privileges or
inspecting thread impersonation tokens.

### Current directory and command line

`helpers::query_process_parameters(handle, print_errors)` returns an owned
`ProcessParameters` with `current_directory: PathBuf` and `command_line: OsString`.
The collector moves these into the corresponding fields of `ProcessData`.
These standard Windows types preserve UTF-16, including unpaired surrogate
values, without a lossy conversion.

The helper queries WoW64 state and selects PEB32 or native PEB64. It reads the
PEB's process-parameters pointer, then a bounded prefix containing the current
directory and command-line descriptors:

| Target layout | PEB ProcessParameters offset | Prefix read | CurrentDirectory descriptor | CommandLine descriptor |
| --- | --- | --- | --- | --- |
| x64 | `0x20` | 128 bytes | `0x38` | `0x70` |
| WoW64 x86 | `0x10` | 72 bytes | `0x24` | `0x40` |

The parameter block must have valid declared sizes and normalized pointers.
Each string descriptor is checked for even UTF-16 lengths, length/capacity
consistency, pointer alignment, and bounded address arithmetic. Reads must
transfer every requested byte. String allocations are bounded by the native
16-bit lengths, and empty strings remain empty owned values. Remote pointers
are passed to the native reader, never dereferenced locally.

`current_directory` is the directory observed at collection time; a process can
change it after startup. `command_line` preserves the full stored command line,
including quoting and arguments. It is not split into an argument vector, and
the target can modify it, so it does not prove the original startup arguments.
The fields are read separately and can change between reads.

The layout follows the [native process-parameter definitions](https://github.com/winsiderss/phnt/blob/master/ntrtl.h),
[WoW64 definitions](https://github.com/winsiderss/phnt/blob/master/ntwow64.h), and
[Windows 11 x64 layout](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_RTL_USER_PROCESS_PARAMETERS).

### Counts of handles owned by the process

`handle_objects::query_process_handle_type_counts(handle, print_errors)` returns an owned
`std::collections::BTreeMap<String, usize>` containing a count for each object
type present in the process's handle snapshot. Keys are native type names such as
`File`, `Process`, `Thread`, and `Event`, sorted by name. Missing types have no map
entry; use `counts.get("File").copied().unwrap_or(0)` when zero is needed.

These counts describe handles owned by the target process. They are separate
from `ObjectData::handle_count`, which counts references to the queried process
object across the system. Each snapshot entry contributes one, even when several
handles refer to the same object.

The helper counts the snapshot's type indices and resolves them through the
native object-type catalog. It queries neither the target handles individually
nor object names. It requires `PROCESS_QUERY_INFORMATION` without
`PROCESS_DUP_HANDLE` or `PROCESS_VM_READ`, and leaves the caller's handle open.
The native layouts follow the [phnt process-handle definitions](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
and [object-type definitions](https://github.com/winsiderss/phnt/blob/master/ntobapi.h).

Both native buffers use initialized pointer-aligned storage, fallible allocation,
and at most eight query attempts when a buffer must grow. Returned lengths,
entry counts, type indices, catalog record spans, and UTF-16 name pointers are
validated before use. An unresolved type or malformed record returns `Err`
without partial counts. A successful empty snapshot returns an empty map.

For example, inside a function returning `std::io::Result<T>` with the existing
test-build module declarations:

```rust
use crate::process_handle_tests::open_process;
use crate::process_telemetry_tests::handle_objects::query_process_handle_type_counts;
use std::os::windows::io::AsHandle;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

let handle = open_process(std::process::id(), PROCESS_QUERY_INFORMATION, false)?;
let counts = query_process_handle_type_counts(handle.as_handle(), false)?;

for (type_name, count) in &counts
{
    println!("{type_name}: {count}");
}
```

Counts describe the handles observed during the query. The target can open or
close handles afterward; retaining the map does not retain those handles.

### Process windows and visibility

`window_objects::query_process_windows(handle, print_errors)` returns
`ProcessWindowData`, also re-exported by `data.rs`. Complete collection stores it
in `ProcessData::window_objects`.

| Field | Type | Meaning |
| --- | --- | --- |
| `handle_count` | `usize` | Number of unique window handles in `windows`; always equals `windows.len()`. |
| `invisible_count` | `usize` | Number of listed windows whose `is_visible` value is false. |
| `windows` | `Vec<WindowData>` | Owned entries sorted by numeric handle, without duplicates. |

Each `WindowData` contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `handle` | `usize` | Opaque numeric `HWND`, without ownership or a validity guarantee after collection. |
| `thread_id` | `u32` | Identifier of the thread that created the window. |
| `is_visible` | `bool` | Whether `IsWindowVisible` returned nonzero when sampled. |

The helper enumerates desktop-app top-level windows and all their descendants,
then message-only windows and their descendants. Every entry is filtered by
the creator's process ID. Descendants are visited even when their parent belongs
to another process. Windows destroyed before their owner can be queried are
skipped. A successful query with no matching windows returns an empty list and
zero counts.

Enumeration covers the collector thread's current desktop, within its window
station and session. It does not switch desktops or inspect other sessions, so
an empty result does not prove that the process has no windows elsewhere.
Window creation, destruction, visibility changes, and HWND reuse can race with
collection. Detected message-window traversal cycles return `Interrupted` for
the caller to retry; other enumeration failures return `Err` without a partial
record.

`IsWindowVisible` checks `WS_VISIBLE` on the window and its ancestors. A child
under a hidden parent counts as invisible even when its own `WS_VISIBLE` bit is
set. Obscured, minimized, off-screen, or DWM-cloaked windows can still report
visible; this is a visibility-style snapshot, not a screen-exposure check.
Message-only windows are included even though they have no visible surface.

Window handles are USER objects and are counted separately from the kernel
object-type map in `handle_type_counts`. This helper does not duplicate, close,
show, hide, or send messages to the target's windows. Stored HWND values must
never be wrapped in `OwnedHandle` or passed to `CloseHandle`.
`PROCESS_QUERY_LIMITED_INFORMATION` or `PROCESS_QUERY_INFORMATION` is sufficient
for the standalone helper; it needs no memory-read or handle-duplication access.

```rust
let window_data = &data.window_objects;
println!("Window handles: {}, invisible: {}", window_data.handle_count, window_data.invisible_count);

for window in &window_data.windows
{
    println!("HWND=0x{:X}, thread={}, visible={}", window.handle, window.thread_id, window.is_visible);
}
```

The implementation follows Microsoft's [EnumWindows contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows),
[descendant enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumchildwindows),
[message-only window lookup](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowexw),
and [visibility semantics](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-iswindowvisible).

## Handle ownership and access

Use [open_process](../../handle.rs) to obtain an `OwnedHandle`. Import
`std::os::windows::io::AsHandle` and pass `handle.as_handle()` to the collector
or helpers. They borrow the process handle and leave closing it to the caller.

| Operation | Process access |
| --- | --- |
| Query object basic information | A valid object handle; process query access is not required. |
| Query process basic information or protection | `PROCESS_QUERY_INFORMATION` or `PROCESS_QUERY_LIMITED_INFORMATION`. |
| Query enabled privileges | Use `PROCESS_QUERY_INFORMATION`; the helper separately requests `TOKEN_QUERY` on the token. |
| Count owned handles by object type | `PROCESS_QUERY_INFORMATION`. |
| Read current directory and command line | Query access plus `PROCESS_VM_READ`. |
| Enumerate process windows on the current desktop | `PROCESS_QUERY_LIMITED_INFORMATION` or `PROCESS_QUERY_INFORMATION`. |
| Collect all seven results | `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ`. |

The [native token-open contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstoken)
specifies `PROCESS_QUERY_INFORMATION`. Complete collection also needs that right
for the handle-type snapshot; `PROCESS_QUERY_LIMITED_INFORMATION` alone is
insufficient. Individual basic-information and protection queries can still use
limited query access.

Parameter collection additionally requires `PROCESS_VM_READ` for the PEB field,
parameter prefix, and string reads. Query-only access is insufficient for a
complete record. `PROCESS_VM_READ` alone does not grant process query access.
Windows can deny process, memory, or token access independently.

## Example: collect and retain current-process metadata

This example uses the existing test-only module names. Add it as a test in
[src/main.rs](../../../main.rs), then run the command below.

```rust
#[test]
fn inspect_generic_process() -> std::io::Result<()>
{
    use crate::process_handle_tests::open_process;
    use crate::process_telemetry_tests::{collect_process_data, ProcessData};
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let process_id = std::process::id();
    let print_errors = false;
    let handle = open_process(process_id, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, print_errors)?;
    let data = collect_process_data(handle.as_handle(), print_errors)?;
    drop(handle);

    assert_eq!(data.process.process_id, process_id as usize);
    println!("PID={}, parent PID={}, PEB=0x{:X}", data.process.process_id, data.process.parent_process_id, data.process.peb_base_address);
    println!("Granted access=0x{:08X}, object handles={}", data.object.granted_access, data.object.handle_count);
    println!("Protection=0x{:02X}, type={}, audit={}, signer={}", data.protection.level, data.protection.protection_type, data.protection.audit, data.protection.signer);
    println!("Current directory: {}", data.current_directory.display());
    println!("Command line: {:?}", data.command_line);
    println!("Window handles: {}, invisible: {}", data.window_objects.handle_count, data.window_objects.invisible_count);

    for privilege in &data.enabled_privileges
    {
        println!("Enabled privilege: {privilege}");
    }

    for (type_name, count) in &data.handle_type_counts
    {
        println!("Handle type {type_name}: {count}");
    }

    let records: Vec<ProcessData> = vec![data];
    assert_eq!(records.len(), 1);

    Ok(())
}
```

```powershell
cargo test inspect_generic_process -- --nocapture
```

For a single query, import its function from
`crate::process_telemetry_tests::helpers` and call it while the process handle
is still open:

```rust
use crate::process_telemetry_tests::helpers::query_process_protection;

let protection = query_process_protection(handle.as_handle(), print_errors)?;
```

## Errors and reporting

All public functions return `std::io::Result`. The `print_errors` argument
controls reporting through [ErrorHandle](../../../ErrorHandle/mod.rs):

- `true` writes failures to stderr.
- `false` suppresses error output while preserving the returned error.
- Successful queries return data without printing it.

| Failure source | Returned error |
| --- | --- |
| Native process, object, or token API | `io::Error` containing `crate::error_handle::NtStatusError`, preserving `status` and `win32_code`. |
| Unexpected lengths, invalid privilege/handle/type records, unresolved handle types, or a missing successful token handle | `io::ErrorKind::InvalidData`. |
| Fallible query/name buffer allocation | `io::ErrorKind::OutOfMemory`. |
| Privilege name lookup | Win32-backed `io::Error` retaining its raw error code. |
| Parameter API export resolution | Win32-backed loader error. |
| Successful parameter memory read with an incomplete transfer | `io::ErrorKind::UnexpectedEof`. |
| Window process-ID lookup or enumeration failure | Win32-backed `io::Error` retaining its raw error code; `Other` if enumeration fails without a code. |
| Detected message-window traversal cycle | `io::ErrorKind::Interrupted`; retry the query. |

For native failures, inspect `error.get_ref()` and downcast to
`crate::error_handle::NtStatusError`. The original NTSTATUS is in that payload,
not `raw_os_error()`. If the token buffer keeps growing beyond three attempts,
the helper returns a native `STATUS_BUFFER_TOO_SMALL` error.
Handle/type buffer retries are limited to eight attempts; exhausting them returns
the last native buffer-size status. Invalid parameter lengths, string descriptors,
addresses, and unnormalized parameter blocks return `InvalidData`.

## Snapshot limits

Collection uses separate queries, so the record is not an atomic snapshot.
Counts, token privileges, and process state can change during or after collection.
Keeping a record does not keep the target process or its remote memory alive.
A stored PID, parent PID, address, or HWND does not guarantee that a later
operation still refers to the same process, memory mapping, or window.

## Verification

Compile the Generic components through the existing test-build declarations:

```powershell
cargo check --tests
```

The Generic folder currently contains no automated tests. This command checks
compilation without executing the helpers. Add the `inspect_generic_process`
example above to exercise complete collection, including handle-type counts,
through the test runner. Exercise window enumeration with known top-level,
child, nested-child, and message-only windows, then hide a parent to check
inherited visibility and query another process to check PID filtering.
Current-process inspection with the required query
access does not require administrator permissions.
