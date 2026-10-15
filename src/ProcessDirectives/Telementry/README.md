# Process telemetry

[Generic/helpers.rs](Generic/helpers.rs) queries general information about an already-open Windows
process handle. It supports process inspection by reporting the handle's granted
access and object counts, the process's basic metadata and PEB address, its
native protection level, and its enabled primary-token privileges.

[Generic/data.rs](Generic/data.rs) is the core collection entry point. It calls
the helpers, converts their native results into typed Rust storage, and returns
one owned `ProcessData` record for future use.

[PE/helpers.rs](PE/helpers.rs) separately obtains the PEB address and mapped
main executable image base for native x64 or WoW64 targets, checking its MZ/PE
signatures before returning the addresses. It also reads and performs basic
validation of a process image's native COFF file header and collects the common
optional-header image-layout fields.

[PE/sections.rs](PE/sections.rs) collects section metadata and numeric remote
addresses for subsequent memory access.

[PE/signatures.rs](PE/signatures.rs) contains labeled byte arrays and an exact
boolean matcher for bytes already obtained through a memory read.

[../imports.rs](../imports.rs) provides the shared typed loader for additional
process/token API exports, currently `NtReadVirtualMemory`.

The helpers accept `BorrowedHandle<'_>` and return snapshots through
`std::io::Result`. The caller owns the handle and keeps it open during each query.
The helpers do not close it, open another process, or dereference the target's PEB.
The privilege helper opens a separate query-only token handle and closes that
token automatically before returning.
Use [../handle.rs](../handle.rs) to acquire an `OwnedHandle` through `NtOpenProcess`.

## Current module setup

The project targets Windows x64. These components are currently included only in
test builds through the following declarations in `src/main.rs`:

- `process_handle_tests` loads `src/ProcessDirectives/handle.rs`.
- `process_imports` loads `src/ProcessDirectives/imports.rs`.
- `process_telemetry_tests` loads `Generic/data.rs`.
- `process_telemetry_tests::helpers` loads `Generic/helpers.rs`.
- `process_pe_tests` loads `PE/helpers.rs`.
- `process_pe_tests::signatures` loads `PE/signatures.rs`.
- `process_pe_tests::sections` loads `PE/sections.rs`.

The runtime still runs the ETW monitor. Telemetry queries have not been connected
to its process-start callbacks. The example below uses the existing test-build
module names, so it can be added to `src/main.rs` without changing that runtime flow.

```text
Telementry/
  README.md
  Generic/
    data.rs
    helpers.rs
  PE/
    helpers.rs
    signatures.rs
    sections.rs
```

## Collection and storage

`collect_process_data(handle: BorrowedHandle<'_>, print_errors: bool)` returns
`io::Result<ProcessData>`. It queries object information, process basic information,
protection information, and enabled privileges, in that order. The first failure
is returned unchanged, and no partial or default record is returned.

| Record field | Stored type | Contents |
| --- | --- | --- |
| `object` | `ObjectData` | `attributes`, `granted_access`, `handle_count`, `pointer_count`, `reserved` |
| `process` | `ProcessBasicData` | `exit_status`, `peb_base_address`, `affinity_mask`, `base_priority`, `process_id`, `parent_process_id` |
| `protection` | `ProcessProtection` | Raw `level` and decoded `protection_type`, `audit`, `signer` |
| `enabled_privileges` | `Vec<String>` | Owned names of enabled primary-token privileges |

Native process identifiers, affinity, and the numeric PEB address retain their
native widths as `usize`. Exit status remains `NTSTATUS`, access rights remain
`PROCESS_ACCESS_RIGHTS`, and object attributes/counts remain `u32`. Reserved object
values are retained as `[u32; 10]` without interpretation.

`ProcessData` owns all its values, contains no handles or borrowed data, and
supports `Debug`, `Clone`, `PartialEq`, and `Eq`. It can outlive the source handle,
be stored in a `Vec<ProcessData>`, or be moved/shared across threads. The process's
PEB address is stored as a number rather than a raw pointer. Retaining that number
does not keep the target memory alive or make it safe to dereference locally.
Collection consists of separate native queries; values can change between queries.

## Available helpers

| Function | Result type | Native operation |
| --- | --- | --- |
| `query_object_basic_information(handle, print_errors)` | `io::Result<PUBLIC_OBJECT_BASIC_INFORMATION>` | `NtQueryObject` with `ObjectBasicInformation` |
| `query_process_basic_information(handle, print_errors)` | `io::Result<PROCESS_BASIC_INFORMATION>` | `NtQueryInformationProcess` with `ProcessBasicInformation` |
| `query_process_protection(handle, print_errors)` | `io::Result<ProcessProtection>` | `NtQueryInformationProcess` with `ProcessProtectionInformation` |
| `query_enabled_process_privileges(handle, print_errors)` | `io::Result<Vec<String>>` | `NtOpenProcessToken(TOKEN_QUERY)` followed by `NtQueryInformationToken(TokenPrivileges)` |

Every `handle` argument is a `BorrowedHandle<'_>`. Import
`std::os::windows::io::AsHandle` and pass `owned_handle.as_handle()`.

### Object basic information

The return type is the existing `windows-sys` `PUBLIC_OBJECT_BASIC_INFORMATION`.

| Field | Meaning |
| --- | --- |
| `Attributes` | Attributes associated with the queried handle. |
| `GrantedAccess` | Access-rights mask actually granted to this handle. |
| `HandleCount` | Number of open handles referring to this object across the system. |
| `PointerCount` | Number of kernel references to this object. |
| `Reserved` | Native reserved fields; the helper does not interpret them. |

`HandleCount` is not the number of handles owned by the target process. An object
query can also succeed for other object types, such as an event; it does not by
itself establish that a handle refers to a process. Counts can change between calls.

### Process basic information

The return type is the existing `windows-sys` `PROCESS_BASIC_INFORMATION`.

| Field | Meaning |
| --- | --- |
| `ExitStatus` | Native process exit status. |
| `PebBaseAddress` | Native PEB address in the target process's address space. |
| `AffinityMask` | Process affinity mask reported by this information class. |
| `BasePriority` | Process base priority. |
| `UniqueProcessId` | Identifier of the queried process. |
| `InheritedFromUniqueProcessId` | Identifier of the parent process at creation. |

Compare `UniqueProcessId` with the expected PID when checking the opened process's
identity. An open handle can survive process termination; metadata is a snapshot
and does not guarantee the process will remain running.

`PebBaseAddress` is a remote address. Print it as a pointer or retain it as an
address for a later memory-read operation; do not dereference it in the caller's
address space. This helper returns the address without reading PEB contents.

### Process protection

`ProcessProtection` contains the original `PS_PROTECTION` byte and its decoded
fields. It is a Rust snapshot, not a buffer to pass back to the native API.

| Field | Meaning |
| --- | --- |
| `level` | Original protection byte. |
| `protection_type` | Low three bits: 0 = none, 1 = protected light/PPL, 2 = fully protected. |
| `audit` | Audit bit, at bit position three. |
| `signer` | High four bits: OS protection signer category. |

Known signer values are 0 (none), 1 (Authenticode), 2 (CodeGen), 3 (Antimalware),
4 (Lsa), 5 (Windows), 6 (WinTcb), 7 (WinSystem), and 8 (App). Numeric values are
preserved even when they are outside these known categories. The signer field is
protection metadata; it does not verify the executable's file signature.

### Enabled process privileges

`query_enabled_process_privileges` opens the process's primary access token and
returns the names of privileges whose attributes contain `SE_PRIVILEGE_ENABLED`.
Entries marked `SE_PRIVILEGE_REMOVED` are excluded. `SE_PRIVILEGE_ENABLED_BY_DEFAULT`
or `SE_PRIVILEGE_USED_FOR_ACCESS` alone does not qualify an entry as currently
enabled. The function inspects privileges in one primary token; it does not
enumerate token objects or thread impersonation tokens.

The helper first asks `NtQueryInformationToken` for the required `TokenPrivileges`
buffer size, then queries into a 32-bit-aligned allocation. It validates the
returned length and privilege count before reading entries, with at most three
data-query attempts if the required buffer grows. Enabled LUIDs are resolved on
the local machine through `LookupPrivilegeNameW`, producing names such as
`SeChangeNotifyPrivilege`.

The result is an owned list in native enumeration order. If no privileges are
enabled, it returns `Ok(Vec::new())`. A lookup failure returns `Err` rather than
an incomplete list. The helper queries existing privilege state without modifying
it; enabled state is a snapshot taken from the opened token.

## Main executable image address

`query_process_pe_address(handle, print_errors)` in `PE/helpers.rs` returns
`io::Result<ProcessPeAddress>` with three owned fields:

| Field | Meaning |
| --- | --- |
| `peb_base_address: usize` | PEB selected for the target: native PEB64 or WoW64 PEB32. |
| `image_base_address: usize` | Main executable's mapped base from the selected PEB's `ImageBaseAddress`. |
| `is_wow64: bool` | Whether the helper selected the 32-bit WoW64 layout. |

The caller is always x64. The helper first queries `ProcessWow64Information`
(class 26). Its nonzero PEB32 address selects WoW64; a zero result selects native
x64 and reuses the generic `query_process_basic_information` helper (class 0).

The image base requires a separate memory read: `NtReadVirtualMemory` reads
exactly four bytes from PEB32 offset `0x08`, or eight bytes from PEB64 offset
`0x10`. WoW64 pointers are zero-extended. The helper checks native return lengths,
pointer arithmetic, transferred byte count, null addresses, and the 32-bit range
of a reported PEB32 address. `print_errors` controls the same shared error system.

Before returning, discovery calls `validate_process_pe_image` on the reported base.
These are numeric remote addresses, not references to memory owned by this
program. A process can modify its PEB, and its memory can change between reads.
The generic `ProcessData` collector remains independent of this memory-read helper.

`windows-sys` 0.61.2 has no `NtReadVirtualMemory` binding, so the PE helper obtains
it from `crate::process_imports::process_apis(print_errors)`. That shared module
resolves the fixed `ntdll` export through `GetProcAddress`, uses a typed x64
signature with `windows-sys` `HANDLE`/`NTSTATUS`, and pins the loaded module before
caching the table. No additional crate is required. A 32-bit caller's
`NtWow64QueryInformationProcess64` path does not apply to this project's x64 target.

### PE image signature validation

`validate_process_pe_image(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool)`
returns `io::Result<usize>`. The returned number is the remote address of the NT
signature at `image_base_address + e_lfanew`, where later NT header parsing would
begin. It can also validate an image base supplied independently of PEB discovery.

The helper performs two bounded native reads:

1. Read the 64-byte DOS header and require `MZ` (`0x5A4D`) at its start.
2. Decode the signed 32-bit `e_lfanew` field at offset `0x3C`; require it to be
   at least 64 so it does not overlap the DOS header. Check address arithmetic,
   then read exactly four bytes at that offset and require `PE\0\0` (`0x00004550`).

It checks the signature at the header's specified offset rather than scanning
for a matching sequence elsewhere. Buffers remain fixed-size stack arrays even
for large offsets. Null bases, overflowing read ranges, invalid offsets, and
signature mismatches return `InvalidData`. Native read failures preserve their
NTSTATUS; a successful call with a short transfer returns `UnexpectedEof`.
`print_errors` controls reporting without suppressing the returned error.

Matching signatures establish only these format markers. They do not prove the
memory is a genuine mapped executable or validate the COFF/optional headers,
entry point, or section table. Later parsing must check its own lengths, offsets,
and RVAs, and the process can change memory after validation.

### COFF file header

`query_process_image_file_header(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool)`
returns `io::Result<IMAGE_FILE_HEADER>`. The result is the existing `windows-sys`
type in `Win32::System::Diagnostics::Debug`; its binding also requires the enabled
`Win32_System_SystemInformation` feature.

The helper reuses `validate_process_pe_image` to obtain the verified NT signature
address, checks arithmetic, and reads exactly 20 bytes immediately after the
four-byte PE signature through the shared native reader. It copies the complete
local buffer into the native header without requiring its byte array to be aligned.
There are no remote Rust pointer dereferences or target-sized allocations.

| Returned field | Type | Contents |
| --- | --- | --- |
| `Machine` | `u16` | Architecture: x86 `0x014C` or x64 `0x8664`. |
| `NumberOfSections` | `u16` | Declared section-table entry count. |
| `TimeDateStamp` | `u32` | Original COFF timestamp value. |
| `PointerToSymbolTable` | `u32` | Original COFF symbol-table file offset. |
| `NumberOfSymbols` | `u32` | Original COFF symbol count. |
| `SizeOfOptionalHeader` | `u16` | Declared optional-header byte length. |
| `Characteristics` | `u16` | Original image flags. |

Basic validation requires a supported machine type, 1–96 sections, the
`IMAGE_FILE_EXECUTABLE_IMAGE` flag, and `SizeOfOptionalHeader` large enough for the
fixed optional-header fields: at least 96 bytes for x86 or 112 bytes for x64.
The size may include a variable number of data directories, so it is not forced
to the common 224/240-byte values. DLLs are accepted when their executable-image
flag is set. Timestamp and symbol metadata are retained without interpretation.

The owned value remains usable after closing the process handle. A malformed
signature, unsupported machine, invalid count/flag/declared size, or overflowing
address produces `InvalidData`; native read errors keep their original NTSTATUS.
`print_errors = false` suppresses reporting while still returning the error.

This helper validates the COFF fields listed above. It does not read or validate
the optional-header magic, data directories, image bounds, or section table.
Those remain separate parsing steps, and the target can change between reads.

### Optional-header layout

`query_process_image_optional_header(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool)`
returns `io::Result<ProcessOptionalHeader>`. It performs one MZ/PE validation and
reuses the same private COFF reader as `query_process_image_file_header`.
The COFF machine, section count, executable flag, and declared optional-header
minimum are checked before reading optional-header bytes.

The helper reads only the first 64 bytes of the optional header with
`NtReadVirtualMemory`. These fields have matching offsets in PE32 and PE32+.
The minimum declared sizes checked by the COFF reader, 96/112 bytes, cover this
prefix; no read or allocation depends on a target-supplied directory count.

| Owned field | Type | Meaning |
| --- | --- | --- |
| `magic` | `u16` | PE32 `0x10B` for x86, or PE32+ `0x20B` for x64. |
| `size_of_image` | `u32` | Declared image size, including headers, in memory. |
| `size_of_headers` | `u32` | Declared total header byte length. |
| `section_alignment` | `u32` | Declared section alignment in memory. |

The magic must match `IMAGE_FILE_HEADER.Machine`. Unknown or ROM-image magic
and mismatched x86/x64 formats return `InvalidData`. Image size, header size,
and alignment must be nonzero; headers must not exceed image size, image size
must be a multiple of section alignment, and the entire declared optional header
must fit inside `SizeOfHeaders`. Declared address ranges are checked for overflow.

The record owns four numeric fields and supports `Debug`, `Clone`, `Copy`,
`PartialEq`, and `Eq`; it remains usable after its process handle closes. It is
not a native API buffer or a complete `IMAGE_OPTIONAL_HEADER32/64`. Data
directories, remaining optional-header fields, section-table entries, and actual
memory mapping extents are not collected or validated by this helper.
Values can change between native reads. Failures follow the existing boolean
reporting policy and preserve native NTSTATUS errors.

### Section metadata and addresses

`query_process_sections(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool)`
in `PE/sections.rs` returns `io::Result<Vec<ProcessSection>>`. Its private
`validate_image_headers` method performs one DOS/PE validation and shares the
validated COFF/optional-header readers with the public header helpers. It returns
a private `ValidatedImage` snapshot containing the checked `image_base_address`,
NT signature address, COFF header, and optional-header layout. A failed check
returns its error before section-table processing; helpers retain responsibility
for reporting through the supplied `print_errors` value.

The collector consumes this snapshot and calculates the section-table address using the declared
`SizeOfOptionalHeader`, checks that the complete table fits inside `SizeOfHeaders`,
then reads all entries in one `NtReadVirtualMemory` call.

The COFF limit of 1–96 sections bounds the fixed read buffer to 3,840 bytes.
Records are parsed in header order into one owned vector; no allocation uses a
section's content size. Allocation failures return `OutOfMemory`, native failures
retain NTSTATUS, and invalid headers/table/ranges return `InvalidData`. A failure
returns no partial list. The same `print_errors` policy applies throughout.

| Record field | Type | Contents |
| --- | --- | --- |
| `name` | `[u8; 8]` | Original section-name bytes, including null padding or a full eight-byte name. |
| `address` | `usize` | Numeric remote address: image base plus section RVA. |
| `size` | `u32` | Declared span: maximum of virtual size and raw-data size. |
| `virtual_address` | `u32` | Original section RVA. |
| `virtual_size` | `u32` | Original declared virtual size. |
| `raw_data_size` | `u32` | Original raw-data byte length on disk. |
| `raw_data_offset` | `u32` | Original raw-data file offset. |
| `characteristics` | `u32` | Original section flags, including declared read/write/execute attributes. |

The declared span includes raw padding when raw size is larger than virtual size
and falls back to raw size when virtual size is zero. An empty section retains
zero span. Each RVA must be a multiple of `SectionAlignment`, and checked
RVA-plus-span arithmetic must remain within `SizeOfImage`.

The collector preserves raw name bytes, including non-UTF-8 values, without
assuming particular names exist. It returns metadata without reading contents,
checking section overlap/order, or querying current page protection. Numeric
addresses remain target addresses; keep the process handle open and use the
native reader for access. Memory can change or become unreadable after collection.
The owned records can outlive their source handle, but retaining them does not
keep the target memory alive.

## Byte signature matching

`contains_signature(read_bytes: &[u8], signature: &[u8]) -> bool` in
[PE/signatures.rs](PE/signatures.rs) searches the provided byte slice for an
exact contiguous match. It returns `true` on the first match, and `false` for
empty patterns, insufficient data, or no match. It uses the standard library's
[slice windows](https://doc.rust-lang.org/std/primitive.slice.html#method.windows),
including overlapping candidates, with no allocation, handles, or memory API calls.

| Array | Literal bytes | Purpose |
| --- | --- | --- |
| `MZ_SIGNATURE` | `4D 5A` | DOS header marker at a PE image base. |
| `PE_SIGNATURE` | `50 45 00 00` | NT header marker at the DOS header's `e_lfanew` offset. |
| `X64_NOP` | `90` | Single-byte NOP; possible instruction padding. |
| `X64_RET` | `C3` | Near RET; possible function return. |
| `X64_INT3` | `CC` | INT3; possible breakpoint or padding byte. |

All bytes, including `0x00`, must match literally. The matcher does not decode
instructions or identify instruction boundaries. Each call searches only its
supplied slice; it does not retain bytes across separate reads.

For `NtReadVirtualMemory` or `ReadProcessMemory`, first check the read's status,
then pass only the successfully transferred bytes: `&buffer[..bytes_read]`.
Passing the entire capacity after a short read can match untouched padding or
stale contents. Read failures remain the memory reader's errors; a `false` result
means no match within the supplied bytes.

The existing `validate_process_pe_image` uses the catalog on the two-byte DOS
prefix and four-byte NT signature read. This preserves its exact header locations;
an unrelated occurrence elsewhere in the DOS header cannot validate an image.

### Usage: scan native-read output

This test function can be added to `src/main.rs` with the current module setup.
It reads the current executable's first 64 bytes and scans only the returned data.

```rust
#[test]
fn inspect_memory_signatures() -> std::io::Result<()>
{
    use crate::error_handle;
    use crate::process_handle_tests::open_process;
    use crate::process_imports::process_apis;
    use crate::process_pe_tests::query_process_pe_address;
    use crate::process_pe_tests::signatures::{contains_signature, MZ_SIGNATURE, PE_SIGNATURE};
    use std::os::windows::io::{AsHandle, AsRawHandle};
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let print_errors = false;
    let handle = open_process(std::process::id(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, print_errors)?;
    let address = query_process_pe_address(handle.as_handle(), print_errors)?;
    let apis = process_apis(print_errors)?;
    let mut buffer = [0_u8; 64];
    let mut bytes_read = 0;

    let status = unsafe
    {
        (apis.nt_read_virtual_memory)(handle.as_raw_handle(), address.image_base_address as *const std::ffi::c_void, buffer.as_mut_ptr().cast(), buffer.len(), &mut bytes_read)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtReadVirtualMemory(signature example)", print_errors));
    }

    let read_bytes = buffer.get(..bytes_read).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "The reader reported more bytes than the buffer can hold."))?;
    let found_mz = contains_signature(read_bytes, &MZ_SIGNATURE);
    let found_pe = contains_signature(read_bytes, &PE_SIGNATURE);

    println!("Read {bytes_read} bytes; MZ found={found_mz}, PE marker found={found_pe}");
    assert!(found_mz);

    Ok(())
}
```

The live handle and initialized writable buffer remain valid throughout the
unsafe call, and the requested size equals the buffer length. A short successful
read searches only its transferred prefix. This example scans the DOS header;
use the NT signature address from `validate_process_pe_image` when the intention
is to read/check the PE marker at its required location.

Run it after adding the example:

```powershell
cargo test inspect_memory_signatures -- --nocapture
```

### Adding a signature

Place a documented fixed byte array alongside the existing constants in
`PE/signatures.rs`, describing the bytes and their intended use. For example:

```rust
/// Example x64 NOP/NOP/RET sequence; a candidate for instruction-pattern inspection.
pub const X64_NOP_NOP_RET: [u8; 3] = [0x90, 0x90, 0xC3];
```

Then call `contains_signature(read_bytes, &X64_NOP_NOP_RET)`. No registry, wrapper,
or matcher change is needed. Arrays and borrowed `Vec<u8>` slices both work.

## Additional process/token API imports

`process_apis(print_errors)` returns the process-lifetime `ProcessApis` table.
Its current field, `nt_read_virtual_memory`, is an unsafe function pointer: the
caller must keep its process handle valid and supply correctly sized writable
local outputs. `PE/helpers.rs` supplies those arguments for its bounded PEB and
PE signature reads.

The shared resolver publishes the table once using `OnceLock`; success and the
original Win32 failure are both cached. Lookup failures use the same boolean
reporting policy, retain their raw Win32 code, and propagate through the PE helper.
Additional dynamic bindings belong in `ProcessDirectives/imports.rs` only when
they serve process/token operations. The public loader accepts no arbitrary
library or export names. Existing `windows-sys` bindings remain direct imports.

## Access rights

Open the process with `PROCESS_QUERY_LIMITED_INFORMATION` or
`PROCESS_QUERY_INFORMATION` for basic-information and protection queries.
`PROCESS_VM_READ` alone does not grant process query access. Reading memory later
requires its own appropriate access rights.

The privilege helper requests only `TOKEN_QUERY` on the token. The native
`NtOpenProcessToken` documentation specifies `PROCESS_QUERY_INFORMATION` on the
process handle; the tests also verify `PROCESS_QUERY_LIMITED_INFORMATION` works
on this Windows system. The example uses `PROCESS_QUERY_INFORMATION` for all four
queries. Token security restrictions can deny access independently of process access.

The object basic-information helper queries a valid object's handle and does not
require process query access. It can therefore inspect the granted access of a
process handle whose basic-information query would be denied.

PE image-address discovery requires query access plus `PROCESS_VM_READ`.
Use `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, or limited query access plus
`PROCESS_VM_READ`. Query-only handles cannot perform the PEB field read.
Standalone `validate_process_pe_image` needs `PROCESS_VM_READ`; it does not query
process information.
`query_process_image_file_header` also needs only `PROCESS_VM_READ` when the image
base is already known.
`query_process_image_optional_header` uses the same access right.
`query_process_sections` also requires `PROCESS_VM_READ` when its image base is
already known; PEB-based discovery additionally requires process query access.

## Usage: inspect the current process

Add this test function to `src/main.rs` to collect and retain a record using the
current module declarations:

```rust
#[test]
fn inspect_current_process() -> std::io::Result<()>
{
    use crate::process_handle_tests::open_process;
    use crate::process_telemetry_tests::{collect_process_data, ProcessData};
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;

    let process_id = std::process::id();
    let print_errors = false;
    let handle = open_process(process_id, PROCESS_QUERY_INFORMATION, print_errors)?;

    let data = collect_process_data(handle.as_handle(), print_errors)?;
    drop(handle);

    assert_eq!(data.process.process_id, process_id as usize);

    println!("Granted access=0x{:08X}, object handles={}, kernel references={}", data.object.granted_access, data.object.handle_count, data.object.pointer_count);
    println!("PID={}, parent PID={}, PEB=0x{:X}", data.process.process_id, data.process.parent_process_id, data.process.peb_base_address);
    println!("Protection=0x{:02X}, type={}, audit={}, signer={}", data.protection.level, data.protection.protection_type, data.protection.audit, data.protection.signer);

    for privilege in &data.enabled_privileges
    {
        println!("Enabled privilege: {privilege}");
    }

    let records: Vec<ProcessData> = vec![data];
    assert_eq!(records.len(), 1);

    Ok(())
}
```

Run it from the project root after adding the example:

```powershell
cargo test inspect_current_process -- --nocapture
```

For another process, replace `std::process::id()` with its PID. The `OwnedHandle`
closes automatically when it goes out of scope; the example closes it explicitly
before using the record to demonstrate independent ownership. For an individual
query, import its function from `crate::process_telemetry_tests::helpers` and pass
`handle.as_handle()` while the handle is still open.

## Usage: inspect the main executable image address

This test function can also be added to `src/main.rs` with the current declarations:

```rust
#[test]
fn inspect_current_image() -> std::io::Result<()>
{
    use crate::process_handle_tests::open_process;
    use crate::process_pe_tests::{query_process_image_file_header, query_process_image_optional_header, query_process_pe_address, validate_process_pe_image};
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let handle = open_process(std::process::id(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false)?;
    let address = query_process_pe_address(handle.as_handle(), false)?;
    let nt_headers_address = validate_process_pe_image(handle.as_handle(), address.image_base_address, false)?;
    let file_header = query_process_image_file_header(handle.as_handle(), address.image_base_address, false)?;
    let optional_header = query_process_image_optional_header(handle.as_handle(), address.image_base_address, false)?;

    println!("PEB=0x{:X}, main image=0x{:X}, WoW64={}", address.peb_base_address, address.image_base_address, address.is_wow64);
    println!("Verified MZ/PE signatures; NT signature address=0x{nt_headers_address:X}");
    println!("Machine=0x{:04X}, sections={}, optional header={} bytes, characteristics=0x{:04X}", file_header.Machine, file_header.NumberOfSections, file_header.SizeOfOptionalHeader, file_header.Characteristics);
    println!("PE magic=0x{:04X}, image size=0x{:X}, header size=0x{:X}, section alignment=0x{:X}", optional_header.magic, optional_header.size_of_image, optional_header.size_of_headers, optional_header.section_alignment);

    Ok(())
}
```

Discovery already checks both signatures. The explicit validation call above
also obtains their NT signature address for subsequent use.

Run it after adding the example:

```powershell
cargo test inspect_current_image -- --nocapture
```

## Usage: access a section

This example collects sections, finds the `.text` record by its exact padded
name, and reads up to 64 bytes from its remote address. Other programs may use
different names; use the returned records to choose the desired section.

```rust
/// Collects the current executable's sections and demonstrates a bounded native read from .text.
/// SAFETY: The live process handle and writable buffer remain valid during the native call; its requested length fits both the buffer and the section's declared span.
#[test]
fn inspect_current_sections() -> std::io::Result<()>
{
    use crate::error_handle;
    use crate::process_handle_tests::open_process;
    use crate::process_imports::process_apis;
    use crate::process_pe_tests::query_process_pe_address;
    use crate::process_pe_tests::sections::query_process_sections;
    use std::os::windows::io::{AsHandle, AsRawHandle};
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let print_errors = false;
    let handle = open_process(std::process::id(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, print_errors)?;
    let image = query_process_pe_address(handle.as_handle(), print_errors)?;
    let sections = query_process_sections(handle.as_handle(), image.image_base_address, print_errors)?;

    for section in &sections
    {
        let name_length = section.name.iter().position(|byte| *byte == 0).unwrap_or(section.name.len());
        let name = String::from_utf8_lossy(&section.name[..name_length]);
        println!("{name}: address=0x{:X}, declared span=0x{:X}, flags=0x{:08X}", section.address, section.size, section.characteristics);
    }

    let text = sections.iter().find(|section| section.name == *b".text\0\0\0").ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "The image has no section named .text."))?;
    let mut buffer = [0_u8; 64];
    let requested = buffer.len().min(text.size as usize);

    if requested == 0
    {
        return Ok(());
    }

    let apis = process_apis(print_errors)?;
    let mut bytes_read = 0;
    let status = unsafe
    {
        (apis.nt_read_virtual_memory)(handle.as_raw_handle(), text.address as *const std::ffi::c_void, buffer.as_mut_ptr().cast(), requested, &mut bytes_read)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtReadVirtualMemory(.text example)", print_errors));
    }

    let read_bytes = buffer[..requested].get(..bytes_read).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "The reader reported more bytes than requested."))?;
    println!("Read {} bytes from .text at 0x{:X}", read_bytes.len(), text.address);

    Ok(())
}
```

Run it after adding the example to `src/main.rs`:

```powershell
cargo test inspect_current_sections -- --nocapture
```

The raw-file offset is for disk access. For a process-memory read, use the
record's `address`; its `size` is a declared range, and actual read failures still
come from the native API. To scan the output, pass only `read_bytes` to
`contains_signature`.

## Errors and console output

- `print_errors = true` reports failures to stderr through
  [ErrorHandle](../../ErrorHandle/mod.rs).
- `print_errors = false` suppresses handler output while still returning `Err`.
- Successful queries return their data without printing it. The example's
  `println!` calls are caller-controlled output.

Native failures retain their original NTSTATUS and converted Win32 code inside
`error_handle::NtStatusError`. Inspect that payload through `error.get_ref()` and
`downcast_ref::<crate::error_handle::NtStatusError>()`; its fields are `status`
and `win32_code`. These typed errors do not expose the native status through
`raw_os_error()`.

Unexpected returned buffer lengths, privilege counts, or malformed PE signatures/
offsets produce a Rust `InvalidData` error. Short successful memory reads produce
`UnexpectedEof`. Fallible token/name buffer allocations report `OutOfMemory`. Privilege name
lookups use the shared Win32 error handlers, retaining their original raw code.
A process query against an event handle produces an object-type failure; a process handle
without query access produces an access-denied failure.

## Verification and references

Run the collection tests from the project root:

```powershell
cargo test process_telemetry_tests
cargo test process_pe_tests
cargo test process_imports
```

They collect all four helper results using full and limited process query access,
retain owned records after closing their handles, share records across threads,
check current PID/PEB/status and granted access, and preserve native failures when
query access is missing. These current-process tests do not require administrator
permissions.

The PE helpers are compiled in test builds; their native-query usage can be
exercised with the `inspect_current_image` example above. It reports the COFF
fields and optional-header image layout for the current executable.
The `inspect_current_sections` example lists section metadata and reads a bounded
prefix from `.text` using the returned remote address.

Import tests invoke the dynamically resolved native memory reader and check a
missing export's captured Win32 error.

Signature tests cover matches at both boundaries, overlapping candidates,
empty/truncated data, and literal zero bytes.

Native contracts and layouts:

- [Microsoft: NtQueryObject and object basic information](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject)
- [Microsoft: NtQueryInformationProcess and process basic information](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)
- [Microsoft: process handles and identifiers](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)
- [Geoff Chappell: x86/x64 PEB field offsets](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)
- [Vergilius: Windows 11 x64 PEB layout](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB)
- [phnt: NtReadVirtualMemory ABI](https://github.com/winsiderss/phnt/blob/master/ntmmapi.h)
- [Microsoft: PE format and signature offsets](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft: IMAGE_FILE_HEADER fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header)
- [Microsoft: IMAGE_SECTION_HEADER fields](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)
- [Microsoft: GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)
- [Microsoft: GetModuleHandleExW and pinning](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexw)
- [Microsoft: NtOpenProcessToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntopenprocesstoken)
- [Microsoft: NtQueryInformationToken](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryinformationtoken)
- [Microsoft: TOKEN_PRIVILEGES and attribute flags](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_privileges)
- [Microsoft: LookupPrivilegeNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegenamew)
- [phnt: PS_PROTECTION layout](https://github.com/winsiderss/phnt/blob/master/ntpsapi.h)
- [NtDoc: PS_PROTECTION](https://ntdoc.m417z.com/ps_protection)
