use crate::error_handle;
use std::ffi::{c_void, CStr};
use std::io;
use std::ptr::null_mut;
use std::sync::OnceLock;
use windows_sys::core::w;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, NTSTATUS};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleExW, GetProcAddress, GET_MODULE_HANDLE_EX_FLAG_PIN};

/// Native process-memory read signature using the Windows x64 SIZE_T ABI.
pub type NtReadVirtualMemory = unsafe extern "system" fn(process_handle: HANDLE, base_address: *const c_void, buffer: *mut c_void, number_of_bytes_to_read: usize, number_of_bytes_read: *mut usize) -> NTSTATUS;

/// Untyped function-pointer form returned by GetProcAddress, used only during private export resolution.
type NativeExport = unsafe extern "system" fn() -> isize;

/// Typed dynamically resolved process/token API exports; extend this table only for APIs needed by those workflows.
#[derive(Debug)]
pub struct ProcessApis
{
    pub nt_read_virtual_memory: NtReadVirtualMemory,
}

/// One immutable process-lifetime API table or the original Win32 loader failure.
static PROCESS_APIS: OnceLock<Result<ProcessApis, u32>> = OnceLock::new();


/// Returns the cached typed process/token API table, optionally reports loader failures, and preserves their original Win32 codes.
/// SAFETY: The private resolver pins ntdll before publishing an export; only the fixed NtReadVirtualMemory export is cast to its matching native x64 signature.
pub fn process_apis(print_errors: bool) -> io::Result<&'static ProcessApis>
{
    let result = PROCESS_APIS.get_or_init(||
    {
        let address = resolve_ntdll_export(c"NtReadVirtualMemory")?;
        let nt_read_virtual_memory = unsafe
        {
            std::mem::transmute::<NativeExport, NtReadVirtualMemory>(address)
        };

        Ok(ProcessApis
        {
            nt_read_virtual_memory,
        })
    });

    match result
    {
        Ok(apis) => Ok(apis),
        Err(code) => Err(error_handle::handle_win32_error(*code, "Loading process/token API NtReadVirtualMemory", print_errors)),
    }
}


/// Resolves a named export from the loaded, pinned ntdll module; returns captured loader failures for reporting at the public entry point.
/// SAFETY: The DLL name and export name are terminated strings valid during each call; successful module pinning keeps all returned function addresses valid until process termination, and the module handle is never freed.
fn resolve_ntdll_export(name: &CStr) -> Result<NativeExport, u32>
{
    let mut module = null_mut();
    let result = unsafe
    {
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN, w!("ntdll.dll"), &mut module)
    };

    if result == 0
    {
        return Err(unsafe
        {
            GetLastError()
        });
    }

    let address = unsafe
    {
        GetProcAddress(module, name.as_ptr().cast())
    };

    match address
    {
        Some(address) => Ok(address),
        None => Err(unsafe
        {
            GetLastError()
        }),
    }
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::process_handle_tests::open_process;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetLastError, ERROR_ACCESS_DENIED, ERROR_PROC_NOT_FOUND, STATUS_SUCCESS};
    use windows_sys::Win32::System::Threading::PROCESS_VM_READ;


    /// Confirms the resolved native function obeys the declared pointer/length ABI and reads the requested bytes.
    /// SAFETY: The process handle is owned for the whole call, the source value stays initialized, and the destination and byte-count outputs remain writable for the requested size.
    #[test]
    fn resolved_memory_read_uses_correct_native_signature()
    {
        let handle = open_process(std::process::id(), PROCESS_VM_READ, false).unwrap();
        let apis = process_apis(false).unwrap();
        let source = 0x0123456789ABCDEF_u64;
        let mut destination = 0_u64;
        let mut bytes_read = 0;
        let status = unsafe
        {
            (apis.nt_read_virtual_memory)(handle.as_raw_handle(), (&source as *const u64).cast(), (&mut destination as *mut u64).cast(), size_of::<u64>(), &mut bytes_read)
        };

        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(bytes_read, size_of::<u64>());
        assert_eq!(destination, source);
    }


    /// Confirms a missing export returns its own Win32 failure rather than a stale thread error or invalid function pointer.
    /// SAFETY: SetLastError changes only this test thread's error slot; the private resolver performs the documented loader calls.
    #[test]
    fn missing_export_preserves_loader_error()
    {
        unsafe
        {
            SetLastError(ERROR_ACCESS_DENIED);
        }

        let code = resolve_ntdll_export(c"RosaryEDR_NonexistentProcessApi_Test").unwrap_err();
        let error = error_handle::handle_win32_error(code, "Resolving missing process API", false);

        assert_eq!(code, ERROR_PROC_NOT_FOUND);
        assert_eq!(error.raw_os_error(), Some(ERROR_PROC_NOT_FOUND as i32));
    }
}
