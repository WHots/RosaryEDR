use crate::error_handle;
use std::io;
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::io::{AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Wdk::Storage::FileSystem::{NtOpenProcessToken, NtQueryInformationToken};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation, ProcessProtectionInformation};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, STATUS_BUFFER_TOO_SMALL};
use windows_sys::Win32::Security::{LookupPrivilegeNameW, TokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED, TOKEN_PRIVILEGES, TOKEN_QUERY};
use windows_sys::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

/// An owned snapshot of PS_PROTECTION's raw byte and decoded protection type, audit flag, and signer category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessProtection
{
    pub level: u8,
    pub protection_type: u8,
    pub audit: bool,
    pub signer: u8,
}


/// Queries a borrowed object's attributes, granted access, handle count, and reference count; optionally reports failures.
/// SAFETY: The borrowed handle remains open during the call, the initialized native structure provides an aligned writable buffer, and the returned length is validated before returning it.
pub fn query_object_basic_information(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<PUBLIC_OBJECT_BASIC_INFORMATION>
{
    let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let size = size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32;
    let mut returned_length = 0;
    let status = unsafe
    {
        NtQueryObject(handle.as_raw_handle(), ObjectBasicInformation, (&mut information as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(), size, &mut returned_length)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtQueryObject(ObjectBasicInformation)", print_errors));
    }

    if returned_length != size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("Object basic information returned {returned_length} bytes; expected {size}."));
        let _ = error_handle::handle_std_error(&error, "NtQueryObject(ObjectBasicInformation)", print_errors);
        return Err(error);
    }

    Ok(information)
}


/// Queries a borrowed process's exit status, PEB address, affinity, priority, PID, and parent PID; optionally reports failures.
/// SAFETY: The borrowed handle remains open during the call and the initialized native structure provides an aligned writable buffer. PebBaseAddress is an address in the target process and is never dereferenced here.
pub fn query_process_basic_information(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<PROCESS_BASIC_INFORMATION>
{
    let mut information = PROCESS_BASIC_INFORMATION::default();
    let size = size_of::<PROCESS_BASIC_INFORMATION>() as u32;
    let mut returned_length = 0;
    let status = unsafe
    {
        NtQueryInformationProcess(handle.as_raw_handle(), ProcessBasicInformation, (&mut information as *mut PROCESS_BASIC_INFORMATION).cast(), size, &mut returned_length)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtQueryInformationProcess(ProcessBasicInformation)", print_errors));
    }

    if returned_length != size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("Process basic information returned {returned_length} bytes; expected {size}."));
        let _ = error_handle::handle_std_error(&error, "NtQueryInformationProcess(ProcessBasicInformation)", print_errors);
        return Err(error);
    }

    Ok(information)
}


/// Queries and decodes a borrowed process's protection byte into an owned snapshot; optionally reports failures.
/// SAFETY: PS_PROTECTION is a single byte, the initialized output byte remains writable during the native call, and the returned length is validated before decoding its bit fields.
pub fn query_process_protection(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<ProcessProtection>
{
    let mut level = 0_u8;
    let size = size_of::<u8>() as u32;
    let mut returned_length = 0;
    
    let status = unsafe
    {
        NtQueryInformationProcess(handle.as_raw_handle(), ProcessProtectionInformation, (&mut level as *mut u8).cast(), size, &mut returned_length)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtQueryInformationProcess(ProcessProtectionInformation)", print_errors));
    }

    if returned_length != size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("Process protection information returned {returned_length} bytes; expected {size}."));
        let _ = error_handle::handle_std_error(&error, "NtQueryInformationProcess(ProcessProtectionInformation)", print_errors);
        return Err(error);
    }

    Ok(ProcessProtection
    {
        level,
        protection_type: level & 0x07,
        audit: level & 0x08 != 0,
        signer: level >> 4,
    })
}


/// Opens a borrowed process's primary token for querying and returns the names of its currently enabled privileges; optionally reports failures.
/// SAFETY: Only a successfully opened token handle is owned, the u32 buffer satisfies native 32-bit alignment, and all writable buffer lengths are supplied accurately to NtQueryInformationToken. OwnedHandle closes the token on every return path.
pub fn query_enabled_process_privileges(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<Vec<String>>
{
    let mut token_handle = null_mut();
    let status = unsafe
    {
        NtOpenProcessToken(handle.as_raw_handle(), TOKEN_QUERY, &mut token_handle)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtOpenProcessToken(TOKEN_QUERY)", print_errors));
    }

    if token_handle.is_null()
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "NtOpenProcessToken reported success without returning a token handle.");
        let _ = error_handle::handle_std_error(&error, "NtOpenProcessToken(TOKEN_QUERY)", print_errors);
        return Err(error);
    }

    let token = unsafe
    {
        OwnedHandle::from_raw_handle(token_handle)
    };

    let mut required_length = 0;
    let status = unsafe
    {
        NtQueryInformationToken(token.as_raw_handle(), TokenPrivileges, null_mut(), 0, &mut required_length)
    };

    if status < 0 && status != STATUS_BUFFER_TOO_SMALL
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtQueryInformationToken(TokenPrivileges) sizing", print_errors));
    }

    if (required_length as usize) < offset_of!(TOKEN_PRIVILEGES, Privileges)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Token privileges returned a size smaller than their header.");
        let _ = error_handle::handle_std_error(&error, "NtQueryInformationToken(TokenPrivileges)", print_errors);
        return Err(error);
    }

    let mut buffer = Vec::<u32>::new();

    for _ in 0..3
    {
        let word_count = (required_length as usize).div_ceil(size_of::<u32>());

        if let Err(reserve_error) = buffer.try_reserve_exact(word_count.saturating_sub(buffer.len()))
        {
            let error = io::Error::new(io::ErrorKind::OutOfMemory, reserve_error);
            let _ = error_handle::handle_std_error(&error, "Allocating token privileges buffer", print_errors);
            return Err(error);
        }

        buffer.resize(word_count, 0);

        let mut returned_length = 0;
        let status = unsafe
        {
            NtQueryInformationToken(token.as_raw_handle(), TokenPrivileges, buffer.as_mut_ptr().cast(), required_length, &mut returned_length)
        };

        if status == STATUS_BUFFER_TOO_SMALL && returned_length > required_length
        {
            required_length = returned_length;
            continue;
        }

        if status < 0
        {
            return Err(error_handle::handle_ntstatus_error(status, "NtQueryInformationToken(TokenPrivileges)", print_errors));
        }

        if returned_length > required_length
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "Token privileges reported more bytes than the supplied query buffer.");
            let _ = error_handle::handle_std_error(&error, "NtQueryInformationToken(TokenPrivileges)", print_errors);
            return Err(error);
        }

        return parse_enabled_privileges(&buffer, returned_length, print_errors);
    }

    Err(error_handle::handle_ntstatus_error(STATUS_BUFFER_TOO_SMALL, "NtQueryInformationToken(TokenPrivileges) after three buffer attempts", print_errors))
}


/// Validates a variable-length token privilege buffer and resolves the names of its enabled, non-removed entries; optionally reports failures.
/// SAFETY: Entry counts are checked against initialized buffer bytes before unaligned copies of integer-only native records. LookupPrivilegeNameW receives live LUIDs and writable UTF-16 buffers, and its returned name length is checked before slicing.
fn parse_enabled_privileges(buffer: &[u32], returned_length: u32, print_errors: bool) -> io::Result<Vec<String>>
{
    let returned_length = returned_length as usize;
    let header_size = offset_of!(TOKEN_PRIVILEGES, Privileges);
    let entry_size = size_of::<LUID_AND_ATTRIBUTES>();

    if returned_length < header_size || returned_length > size_of_val(buffer)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Token privileges returned an invalid buffer length.");
        let _ = error_handle::handle_std_error(&error, "Reading TokenPrivileges", print_errors);
        return Err(error);
    }

    let count = buffer[0] as usize;

    if count > (returned_length - header_size) / entry_size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Token privilege count exceeds the returned buffer.");
        let _ = error_handle::handle_std_error(&error, "Reading TokenPrivileges", print_errors);
        return Err(error);
    }

    let mut enabled = Vec::new();

    for index in 0..count
    {
        let privilege = unsafe
        {
            buffer.as_ptr().cast::<u8>().add(header_size + index * entry_size).cast::<LUID_AND_ATTRIBUTES>().read_unaligned()
        };

        if privilege.Attributes & SE_PRIVILEGE_ENABLED == 0 || privilege.Attributes & SE_PRIVILEGE_REMOVED != 0
        {
            continue;
        }

        let mut name_length = 0;
        let result = unsafe
        {
            LookupPrivilegeNameW(null(), &privilege.Luid, null_mut(), &mut name_length)
        };

        if result == 0
        {
            let code = unsafe
            {
                GetLastError()
            };

            if code != ERROR_INSUFFICIENT_BUFFER
            {
                return Err(error_handle::handle_win32_error(code, "LookupPrivilegeNameW sizing", print_errors));
            }
        }

        let mut name_buffer = Vec::<u16>::new();

        if let Err(reserve_error) = name_buffer.try_reserve_exact(name_length as usize + 1)
        {
            let error = io::Error::new(io::ErrorKind::OutOfMemory, reserve_error);
            let _ = error_handle::handle_std_error(&error, "Allocating privilege name buffer", print_errors);
            return Err(error);
        }

        name_buffer.resize(name_length as usize + 1, 0);
        name_length = name_buffer.len() as u32;

        let result = unsafe
        {
            LookupPrivilegeNameW(null(), &privilege.Luid, name_buffer.as_mut_ptr(), &mut name_length)
        };

        if result == 0
        {
            return Err(error_handle::handle_last_error("LookupPrivilegeNameW", print_errors));
        }

        if name_length as usize > name_buffer.len()
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "Privilege name length exceeds its returned buffer.");
            let _ = error_handle::handle_std_error(&error, "LookupPrivilegeNameW", print_errors);
            return Err(error);
        }

        enabled.push(String::from_utf16_lossy(&name_buffer[..name_length as usize]));
    }

    Ok(enabled)
}

