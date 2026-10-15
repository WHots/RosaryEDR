# PE process telemetry

The PE folder inspects a mapped Portable Executable image in an already-open
Windows process. It discovers the main executable's image base, checks selected
headers, collects section metadata, and provides exact byte-signature matching.

The caller is Windows x64. Image parsing supports x86 PE32 and x64 PE32+ images;
main-image discovery selects the native x64 or WoW64 PEB layout. See the
[Generic README](../Generic/README.md) for general process metadata and the
[telemetry README](../README.md) for the broader inspection workflow.

## Files and current integration

| File | Responsibility |
| --- | --- |
| [helpers.rs](helpers.rs) | Main-image discovery, MZ/PE validation, COFF and optional-header queries, and the private exact-length memory reader. |
| [sections.rs](sections.rs) | Bounded section-table reads and owned section records. |
| [signatures.rs](signatures.rs) | Labeled byte arrays and an allocation-free exact matcher. |

[src/main.rs](../../../main.rs) loads `helpers.rs` as
`crate::process_pe_tests` only in test builds. That module exposes
`process_pe_tests::sections` and `process_pe_tests::signatures`.
It depends on the existing `process_imports`, `process_telemetry_tests`, and
`error_handle` modules.

The runtime starts the ETW monitor. These helpers are not yet invoked from
process-start callbacks or included in Generic's `collect_process_data`.

## Public API

The process-query functions take `BorrowedHandle<'_>` and `print_errors: bool`.
Header and section queries also take a numeric `image_base_address: usize`.

| Function | Result | Work performed |
| --- | --- | --- |
| `query_process_pe_address(handle, print_errors)` | `io::Result<ProcessPeAddress>` | Selects the PEB, reads its main image base, and validates MZ/PE markers. |
| `validate_process_pe_image(handle, image_base_address, print_errors)` | `io::Result<usize>` | Checks MZ/PE markers and returns the remote NT signature address. |
| `query_process_image_file_header(handle, image_base_address, print_errors)` | `io::Result<IMAGE_FILE_HEADER>` | Validates MZ/PE markers and selected COFF fields. |
| `query_process_image_optional_header(handle, image_base_address, print_errors)` | `io::Result<ProcessOptionalHeader>` | Also checks common optional-header layout fields. |
| `sections::query_process_sections(handle, image_base_address, print_errors)` | `io::Result<Vec<ProcessSection>>` | Validates headers, reads the section table, and checks declared section ranges. |
| `signatures::contains_signature(read_bytes, signature)` | `bool` | Searches caller-supplied byte slices; takes no handle or reporting flag. |

The image-base argument refers to a mapped image in the target's address space,
not a local pointer or a file offset. Callers with an independently known image
base can use the header and section APIs without PEB-based discovery.

## Main executable address

`ProcessPeAddress` owns three fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `peb_base_address` | `usize` | Selected native PEB64 or WoW64 PEB32 address. |
| `image_base_address` | `usize` | Main executable's mapped base reported by that PEB. |
| `is_wow64` | `bool` | Whether discovery selected the WoW64 layout. |

Discovery queries `NtQueryInformationProcess(ProcessWow64Information)`.
A nonzero result selects PEB32; zero selects the native PEB obtained through
Generic's `query_process_basic_information`.

It then reads only the selected PEB's `ImageBaseAddress` field:

| Target layout | Field offset | Bytes read |
| --- | --- | --- |
| Native x64 | `0x10` | 8 |
| WoW64 x86 | `0x08` | 4, zero-extended into the x64 result |

Returned query lengths, nonzero addresses, the PEB32 address range, read-range
arithmetic, and exact transfer lengths are checked. The reported image base is
passed through `validate_process_pe_image` before discovery returns.

The offsets follow [PEB field layouts](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)
and the [Windows 11 x64 layout](https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_PEB).
The PEB is an internal structure; Microsoft's [PEB reference](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
documents that its layout may change.

## Header validation

Each public query performs the checks needed for its own result. Calling the
COFF helper does not perform optional-header or section-table validation.

### MZ and PE markers

`validate_process_pe_image` performs two bounded reads:

1. Read the 64-byte DOS header and require `MZ` at the image base.
2. Read signed `e_lfanew` at DOS offset `0x3C`; require a value of at least 64,
   check address arithmetic, and read exactly four bytes at that offset to
   require `PE\0\0`.

The returned `usize` is `image_base_address + e_lfanew`, the remote address of
the NT signature. The checks preserve the required marker positions; a matching
sequence elsewhere does not validate an image. No buffer size depends on
`e_lfanew`.

These checks validate only the format markers and offset arithmetic. They do not
validate the later headers, prove image authenticity, or verify a file signature.

### COFF file header

`query_process_image_file_header` reads the complete 20-byte COFF header after
the NT signature. It returns the existing `windows-sys`
`IMAGE_FILE_HEADER` from `Win32::System::Diagnostics::Debug`.

| Native field | Type | Meaning |
| --- | --- | --- |
| `Machine` | `u16` | x86 `0x014C` or x64 `0x8664`. |
| `NumberOfSections` | `u16` | Declared section count. |
| `TimeDateStamp` | `u32` | Original COFF timestamp. |
| `PointerToSymbolTable` | `u32` | Original symbol-table file offset. |
| `NumberOfSymbols` | `u32` | Original symbol count. |
| `SizeOfOptionalHeader` | `u16` | Declared optional-header byte length. |
| `Characteristics` | `u16` | Original image flags. |

The checks require a supported machine, 1–96 sections,
`IMAGE_FILE_EXECUTABLE_IMAGE`, and a declared optional-header size of at least
96 bytes for x86 or 112 bytes for x64. The size is not forced to the common
224/240-byte values. DLLs with the executable-image flag are accepted.
Timestamp and symbol metadata are preserved without interpretation.

### Common optional-header layout

`query_process_image_optional_header` validates MZ/PE and COFF data, then reads
the first 64 bytes of the optional header. The returned `ProcessOptionalHeader`
contains four owned fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `magic` | `u16` | PE32 `0x10B` or PE32+ `0x20B`, matching the COFF machine. |
| `size_of_image` | `u32` | Declared image size in memory. |
| `size_of_headers` | `u32` | Declared combined header size. |
| `section_alignment` | `u32` | Declared section alignment in memory. |

Image size, header size, and alignment must be nonzero. Headers must fit inside
the image, `SizeOfImage` must be a multiple of `SectionAlignment`, and the entire
declared optional header must fit inside `SizeOfHeaders`. Address ranges must
not overflow.

This record is not a complete `IMAGE_OPTIONAL_HEADER32/64`. The helper does
not collect data directories, verify all remaining header fields, or query the
actual memory mapping's extents. See Microsoft's
[PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
for the full header and section layouts.

## Section metadata and remote addresses

`sections::query_process_sections` reuses the shared MZ/PE, COFF, and
optional-header readers through a private `ValidatedImage` snapshot. It computes
the section-table address using the declared `SizeOfOptionalHeader`, checks
that the complete table fits inside `SizeOfHeaders`, and reads it once.

The 96-section limit bounds the stack buffer to 3,840 bytes. The returned vector
owns its records in section-table order. Allocation depends on section count,
not on the declared sizes of section contents.

| ProcessSection field | Type | Meaning |
| --- | --- | --- |
| `name` | `[u8; 8]` | Raw section-name bytes; may fill all eight bytes or contain non-UTF-8 data. |
| `address` | `usize` | Remote image base plus section RVA. |
| `size` | `u32` | Declared span: `max(virtual_size, raw_data_size)`. |
| `virtual_address` | `u32` | Original section RVA. |
| `virtual_size` | `u32` | Original declared virtual size. |
| `raw_data_size` | `u32` | Original file-backed data size. |
| `raw_data_offset` | `u32` | Original file offset, not a remote memory address. |
| `characteristics` | `u32` | Original section flags. |

Each RVA must be a multiple of `SectionAlignment`. Checked RVA-plus-span
arithmetic must stay within `SizeOfImage`, and computing the remote address
must not overflow. Zero-sized sections retain a zero span. A failed query or
validation returns no partial list.

The collector does not read section contents, reject overlapping sections, or
check their ordering. Section characteristics describe declared header flags;
they do not establish the current memory-page protection. A declared span does
not guarantee that every byte is currently readable.

`ProcessPeAddress`, `ProcessOptionalHeader`, and `ProcessSection` support
`Debug`, `Clone`, `Copy`, `PartialEq`, and `Eq`. Their owned numeric metadata
can outlive the source handle. Retaining it does not keep the target memory alive.

## Exact byte signatures

[signatures.rs](signatures.rs) exposes these arrays:

| Constant | Bytes | Label |
| --- | --- | --- |
| `MZ_SIGNATURE` | `4D 5A` | DOS header marker. |
| `PE_SIGNATURE` | `50 45 00 00` | NT header marker. |
| `X64_NOP` | `90` | Single-byte NOP encoding. |
| `X64_RET` | `C3` | Single-byte near RET encoding. |
| `X64_INT3` | `CC` | Single-byte INT3 encoding. |

`contains_signature(read_bytes: &[u8], signature: &[u8]) -> bool` searches for
an exact contiguous match, including overlapping candidates. Empty patterns,
insufficient data, and absent matches return `false`. Zero bytes are literal;
there are no wildcards, allocations, or memory API calls.

For a successful memory read, pass only the transferred bytes:
`contains_signature(&buffer[..bytes_read], &signature)`. Check the reader's
status and ensure `bytes_read <= buffer.len()` before slicing. Searching unused
buffer space can match stale contents or padding. Separate calls do not match
signatures split across read boundaries.

An opcode-byte match does not establish an instruction boundary, executable
code, or malicious behavior. This matcher is not a disassembler.

## Access, ownership, and errors

Acquire an `OwnedHandle` with [open_process](../../handle.rs), import
`std::os::windows::io::AsHandle`, and pass `handle.as_handle()`.
The helpers borrow the process handle and never close it.

| Operation | Required process access |
| --- | --- |
| Main-image discovery through the PEB | Query access plus `PROCESS_VM_READ`. |
| Header validation or section collection with a known image base | `PROCESS_VM_READ`. |
| Signature matching on local bytes | No process handle. |

For discovery, use `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`, or
`PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`. Query-only access cannot
read the PEB field or headers, and Windows may deny access to a target process.

All remote reads use the typed `NtReadVirtualMemory` pointer supplied by
[imports.rs](../../imports.rs). That loader resolves the existing `ntdll.dll`
export and pins the module. The private PE reader checks range arithmetic and
requires every requested byte to be transferred.

Failures use [ErrorHandle](../../../ErrorHandle/README.md):

| Failure | Result |
| --- | --- |
| Native process query or memory read | `io::Error` preserving NTSTATUS and its mapped Win32 code. |
| Native API export resolution | Win32-backed loader error. |
| Invalid markers, headers, sizes, addresses, or ranges | `io::ErrorKind::InvalidData`. |
| Successful memory read with a short transfer | `io::ErrorKind::UnexpectedEof`. |
| Section-vector reservation failure | `io::ErrorKind::OutOfMemory`. |

`print_errors = true` reports failures to stderr. Passing `false` suppresses
reporting while still returning errors. Successful queries do not print output.
The signature matcher returns only a boolean.

## Example: inspect the current image and its sections

Add this test to [src/main.rs](../../../main.rs) to use the existing test-only
module declarations:

```rust
#[test]
fn inspect_process_pe() -> std::io::Result<()>
{
    use crate::process_handle_tests::open_process;
    use crate::process_pe_tests::{query_process_image_file_header, query_process_image_optional_header, query_process_pe_address};
    use crate::process_pe_tests::sections::query_process_sections;
    use std::os::windows::io::AsHandle;
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

    let print_errors = false;
    let handle = open_process(std::process::id(), PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, print_errors)?;
    let image = query_process_pe_address(handle.as_handle(), print_errors)?;
    let coff = query_process_image_file_header(handle.as_handle(), image.image_base_address, print_errors)?;
    let optional = query_process_image_optional_header(handle.as_handle(), image.image_base_address, print_errors)?;
    let sections = query_process_sections(handle.as_handle(), image.image_base_address, print_errors)?;
    drop(handle);

    println!("PEB=0x{:X}, image=0x{:X}, WoW64={}", image.peb_base_address, image.image_base_address, image.is_wow64);
    println!("Machine=0x{:04X}, sections={}, image size=0x{:X}", coff.Machine, coff.NumberOfSections, optional.size_of_image);

    for section in &sections
    {
        let name_end = section.name.iter().position(|&byte| byte == 0).unwrap_or(section.name.len());
        let name = String::from_utf8_lossy(&section.name[..name_end]);
        println!("Section {}: address=0x{:X}, span=0x{:X}, flags=0x{:08X}", name.escape_debug(), section.address, section.size, section.characteristics);
    }

    Ok(())
}
```

After adding the example, run:

```powershell
cargo test inspect_process_pe -- --nocapture
```

The example closes the handle before printing to demonstrate that metadata is
owned. To read section contents, keep the process handle open and use the
[bounded section-read example](../README.md#usage-access-a-section).

For matching bytes already obtained by a caller:

```rust
use crate::process_pe_tests::signatures::{contains_signature, X64_RET};

let read_bytes = [0x90, 0x90, 0xC3];
assert!(contains_signature(&read_bytes, &X64_RET));
```

## Snapshot limits and verification

The PEB and mapped headers are target-controlled, and each query performs
separate native reads. Results are not an atomic snapshot. Memory can change,
be unmapped, or become inaccessible after validation. The checks cover the
specific fields described above; they do not establish image authenticity or
complete PE validity.

Compile the PE components through the existing test-build declarations:

```powershell
cargo check --tests
```

The PE folder currently contains no automated tests, including for the signature
matcher. This command checks compilation without executing the helpers. The
example above can be added to exercise current-process inspection through the
test runner; it does not require administrator permissions for the current process.
