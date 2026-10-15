use crate::error_handle;
use std::collections::BTreeMap;
use std::ffi::c_void;
use std::io;
use std::mem::{align_of, size_of, size_of_val};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::ptr::null_mut;
use windows_sys::Wdk::Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessHandleInformation};
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_INFO_LENGTH_MISMATCH, UNICODE_STRING};
use windows_sys::Win32::Security::GENERIC_MAPPING;



/// Native object-type catalog information class, absent from windows-sys 0.61.2.
const OBJECT_TYPES_INFORMATION_CLASS: OBJECT_INFORMATION_CLASS = 3;

/// Native x64 PROCESS_HANDLE_TABLE_ENTRY_INFO layout, absent from windows-sys 0.61.2.
#[repr(C)]
struct ProcessHandleEntry
{
    handle_value: usize,
    handle_count: usize,
    pointer_count: usize,
    granted_access: u32,
    object_type_index: u32,
    handle_attributes: u32,
    reserved: u32,
}

/// Native Windows 10+ OBJECT_TYPE_INFORMATION layout; statistics include the thirteen ULONG fields preceding GenericMapping.
#[repr(C)]
struct ObjectTypeInformation
{
    type_name: UNICODE_STRING,
    statistics: [u32; 13],
    generic_mapping: GENERIC_MAPPING,
    valid_access_mask: u32,
    security_required: u8,
    maintain_handle_count: u8,
    type_index: u8,
    reserved_byte: u8,
    pool_type: u32,
    default_paged_pool_charge: u32,
    default_non_paged_pool_charge: u32,
}


/// Counts a borrowed process's owned handles by native object-type name; returns a sorted owned map or an optionally reported failure, requiring PROCESS_QUERY_INFORMATION.
/// SAFETY: The query helper supplies initialized pointer-aligned buffers and exact writable lengths. Native snapshot entries and catalog names are validated before parsing; target handle values are never used or closed.
pub fn query_process_handle_type_counts(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<BTreeMap<String, usize>>
{
    let (buffer, returned_length) = query_handle_type_buffer(|buffer, length, returned_length| unsafe
    {
        NtQueryInformationProcess(handle.as_raw_handle(), ProcessHandleInformation, buffer, length, returned_length)
    }, "NtQueryInformationProcess(ProcessHandleInformation)", print_errors)?;

    let counts = count_snapshot_handle_types(&buffer, returned_length, print_errors)?;
    drop(buffer);

    if counts.iter().all(|&count| count == 0)
    {
        return Ok(BTreeMap::new());
    }

    let (buffer, returned_length) = query_handle_type_buffer(|buffer, length, returned_length| unsafe
    {
        NtQueryObject(null_mut(), OBJECT_TYPES_INFORMATION_CLASS, buffer, length, returned_length)
    }, "NtQueryObject(ObjectTypesInformation)", print_errors)?;

    resolve_handle_type_counts(&buffer, returned_length, counts, print_errors)
}


/// Reads bounded process-handle snapshot entries into counts by type index; malformed lengths or indices return an optionally reported InvalidData error.
/// SAFETY: The two-usize header and complete entry count are bounded by initialized bytes before unaligned copies of integer-only native entries.
fn count_snapshot_handle_types(buffer: &[usize], returned_length: usize, print_errors: bool) -> io::Result<[usize; 256]>
{
    let header_size = size_of::<[usize; 2]>();
    let entry_size = size_of::<ProcessHandleEntry>();

    if returned_length < header_size || returned_length > size_of_val(buffer)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Process handle information returned an invalid buffer length.");
        let _ = error_handle::handle_std_error(&error, "Reading process handle types", print_errors);
        return Err(error);
    }

    let count = buffer[0];

    if count > (returned_length - header_size) / entry_size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The process handle count exceeds the returned snapshot buffer.");
        let _ = error_handle::handle_std_error(&error, "Reading process handle types", print_errors);
        return Err(error);
    }

    let mut counts = [0_usize; 256];

    for index in 0..count
    {
        let entry = unsafe
        {
            buffer.as_ptr().cast::<u8>().add(header_size + index * entry_size).cast::<ProcessHandleEntry>().read_unaligned()
        };

        let Some(type_count) = counts.get_mut(entry.object_type_index as usize) else
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "A process handle has an object-type index outside the native byte range.");
            let _ = error_handle::handle_std_error(&error, "Reading process handle types", print_errors);
            return Err(error);
        };

        *type_count += 1;
    }

    Ok(counts)
}


/// Resolves snapshot counts through the bounded native type catalog; returns owned nonzero counts ordered by name, or an optionally reported InvalidData error.
/// SAFETY: Headers, variable record spans, UTF-16 lengths, alignment, and name-pointer offsets are checked against initialized returned bytes. Name slices are derived from the local allocation, and no native pointer escapes.
fn resolve_handle_type_counts(buffer: &[usize], returned_length: usize, mut counts: [usize; 256], print_errors: bool) -> io::Result<BTreeMap<String, usize>>
{
    if returned_length < size_of::<u32>() || returned_length > size_of_val(buffer)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Object-type information returned an invalid buffer length.");
        let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
        return Err(error);
    }

    let type_count = buffer[0] as u32 as usize;
    let mut offset = size_of::<u32>().next_multiple_of(align_of::<usize>());
    let header_size = size_of::<ObjectTypeInformation>();
    let mut seen = [false; 256];
    let mut result = BTreeMap::new();

    if type_count > returned_length.saturating_sub(offset) / header_size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The object-type count exceeds the returned catalog buffer.");
        let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
        return Err(error);
    }

    for _ in 0..type_count
    {
        if offset > returned_length || returned_length - offset < header_size
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "An object-type header extends beyond the returned catalog buffer.");
            let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
            return Err(error);
        }

        let information = unsafe
        {
            buffer.as_ptr().cast::<u8>().add(offset).cast::<ObjectTypeInformation>().read_unaligned()
        };

        let header_end = offset + header_size;
        let name_length = information.type_name.Length as usize;
        let maximum_length = information.type_name.MaximumLength as usize;
        let name_offset = (information.type_name.Buffer as usize).checked_sub(buffer.as_ptr() as usize);

        if name_length == 0 || !name_length.is_multiple_of(size_of::<u16>()) || !maximum_length.is_multiple_of(size_of::<u16>()) || name_length > maximum_length || maximum_length > returned_length - header_end
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "An object type has an invalid UTF-16 name length or record span.");
            let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
            return Err(error);
        }

        let record_end = header_end + maximum_length;
        let Some(name_offset) = name_offset.filter(|&start| start >= header_end && start <= record_end && start.is_multiple_of(align_of::<u16>()) && name_length <= record_end - start) else
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "An object-type name points outside its returned record.");
            let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
            return Err(error);
        };

        let type_index = information.type_index as usize;

        if seen[type_index]
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "The object-type catalog contains a repeated type index.");
            let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
            return Err(error);
        }

        seen[type_index] = true;

        if counts[type_index] != 0
        {
            let name = unsafe
            {
                std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>().add(name_offset).cast::<u16>(), name_length / size_of::<u16>())
            };

            if result.insert(String::from_utf16_lossy(name), counts[type_index]).is_some()
            {
                let error = io::Error::new(io::ErrorKind::InvalidData, "The object-type catalog contains a repeated type name.");
                let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
                return Err(error);
            }

            counts[type_index] = 0;
        }

        offset = record_end.next_multiple_of(align_of::<usize>());
    }

    if counts.iter().any(|&count| count != 0)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The object-type catalog did not resolve every handle type in the process snapshot.");
        let _ = error_handle::handle_std_error(&error, "Resolving process handle types", print_errors);
        return Err(error);
    }

    Ok(result)
}


/// Queries a variable-length native handle/type buffer with at most eight growth attempts; returns aligned owned storage and its validated byte count, optionally reporting failures.
fn query_handle_type_buffer(mut query: impl FnMut(*mut c_void, u32, *mut u32) -> NTSTATUS, context: &str, print_errors: bool) -> io::Result<(Vec<usize>, usize)>
{
    let mut buffer = Vec::<usize>::new();
    let mut length = 0x8000_u32;
    let mut last_status = STATUS_INFO_LENGTH_MISMATCH;

    for _ in 0..8
    {
        let word_count = (length as usize).div_ceil(size_of::<usize>());

        if let Err(allocation_error) = buffer.try_reserve_exact(word_count.saturating_sub(buffer.len()))
        {
            let error = io::Error::new(io::ErrorKind::OutOfMemory, allocation_error);
            let _ = error_handle::handle_std_error(&error, context, print_errors);
            return Err(error);
        }

        buffer.resize(word_count, 0);
        buffer.fill(0);

        let mut returned_length = 0;
        let status = query(buffer.as_mut_ptr().cast(), length, &mut returned_length);

        if status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL || status == STATUS_BUFFER_OVERFLOW
        {
            last_status = status;

            if returned_length > length
            {
                length = returned_length;
            }
            else if let Some(next_length) = length.checked_mul(2)
            {
                length = next_length;
            }
            else
            {
                let error = io::Error::new(io::ErrorKind::OutOfMemory, "The native handle/type buffer exceeds the supported query size.");
                let _ = error_handle::handle_std_error(&error, context, print_errors);
                return Err(error);
            }

            continue;
        }

        if status < 0
        {
            return Err(error_handle::handle_ntstatus_error(status, context, print_errors));
        }

        if returned_length == 0 || returned_length > length
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "Native handle/type information returned an invalid buffer length.");
            let _ = error_handle::handle_std_error(&error, context, print_errors);
            return Err(error);
        }

        return Ok((buffer, returned_length as usize));
    }

    Err(error_handle::handle_ntstatus_error(last_status, &format!("{context} after eight buffer attempts"), print_errors))
}
