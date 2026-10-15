use crate::error_handle;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::System::Threading::NtOpenProcess;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;
use windows_sys::Win32::System::WindowsProgramming::CLIENT_ID;


/// Opens a PID with explicit desired access and optional console errors; returns a non-inheritable owned handle or the original failure.
/// SAFETY: NtOpenProcess receives initialized, correctly sized live structures; the PID is an opaque client identifier, and only a successfully opened handle is transferred to OwnedHandle.
pub fn open_process(process_id: u32, desired_access: PROCESS_ACCESS_RIGHTS, print_errors: bool) -> io::Result<OwnedHandle>
{
    if desired_access == 0
    {
        let error = io::Error::new(io::ErrorKind::InvalidInput, "A nonzero process access mask is required.");
        let _ = error_handle::handle_std_error(&error, "NtOpenProcess", print_errors);
        return Err(error);
    }

    let attributes = OBJECT_ATTRIBUTES
    {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };

    let client_id = CLIENT_ID
    {
        UniqueProcess: process_id as usize as HANDLE,
        UniqueThread: null_mut(),
    };

    let mut handle = null_mut();
    let status = unsafe
    {
        NtOpenProcess(&mut handle, desired_access, &attributes, &client_id)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, &format!("NtOpenProcess(PID={process_id}, desired_access=0x{desired_access:08X})"), print_errors));
    }

    if handle.is_null()
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "NtOpenProcess reported success without returning a process handle.");
        let _ = error_handle::handle_std_error(&error, "NtOpenProcess", print_errors);
        return Err(error);
    }

    Ok(unsafe
    {
        OwnedHandle::from_raw_handle(handle)
    })
}