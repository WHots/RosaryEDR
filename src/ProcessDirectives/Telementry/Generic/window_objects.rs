use crate::error_handle;
use std::collections::HashSet;
use std::io;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use std::ptr::{null, null_mut};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{GetLastError, SetLastError, HWND, LPARAM};
use windows_sys::Win32::System::Threading::GetProcessId;
use windows_sys::Win32::UI::WindowsAndMessaging::{EnumChildWindows, EnumWindows, FindWindowExW, GetWindowThreadProcessId, IsWindowVisible, HWND_MESSAGE};

/// One window snapshot; handle is an opaque HWND value, not an owned kernel handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowData
{
    pub handle: usize,
    pub thread_id: u32,
    pub is_visible: bool,
}


/// Owned, deduplicated windows and counts observed on the collector's current desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessWindowData
{
    pub handle_count: usize,
    pub invisible_count: usize,
    pub windows: Vec<WindowData>,
}


/// Synchronous enumeration state; callbacks defer failures to the public helper for optional reporting.
struct WindowEnumeration
{
    process_id: u32,
    windows: Vec<WindowData>,
    error: Option<io::Error>,
}


/// Lists a borrowed process's top-level, descendant, and message-only windows on the current desktop; query access is required, and print_errors controls failure reporting.
/// SAFETY: Enumeration callbacks are synchronous and receive a live stack context. Remote HWND values are queried without taking ownership or sending messages; results retain only integers and booleans.
pub fn query_process_windows(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<ProcessWindowData>
{
    let result = (||
    {
        let process_id = unsafe
        {
            GetProcessId(handle.as_raw_handle())
        };

        if process_id == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut enumeration = WindowEnumeration
        {
            process_id,
            windows: Vec::new(),
            error: None,
        };
        let parameter = (&raw mut enumeration) as LPARAM;

        let (success, error_code) = unsafe
        {
            SetLastError(0);
            let success = EnumWindows(Some(enumerate_window_tree), parameter);
            (success, GetLastError())
        };

        if let Some(error) = enumeration.error.take()
        {
            return Err(error);
        }

        if success == 0
        {
            if error_code == 0
            {
                return Err(io::Error::other("EnumWindows failed without an extended error code."));
            }

            return Err(io::Error::from_raw_os_error(error_code as i32));
        }

        let mut seen_message_windows = HashSet::new();
        let mut previous = null_mut();

        loop
        {
            let (window, error_code) = unsafe
            {
                SetLastError(0);
                let window = FindWindowExW(HWND_MESSAGE, previous, null(), null());
                (window, GetLastError())
            };

            if window.is_null()
            {
                if error_code != 0
                {
                    return Err(io::Error::from_raw_os_error(error_code as i32));
                }

                break;
            }

            seen_message_windows.try_reserve(1).map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;

            if !seen_message_windows.insert(window as usize)
            {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "The message-only window list changed during enumeration; retry the query."));
            }

            unsafe
            {
                enumerate_window_tree(window, parameter);
            }

            if let Some(error) = enumeration.error.take()
            {
                return Err(error);
            }

            previous = window;
        }

        enumeration.windows.sort_unstable_by_key(|window| window.handle);
        enumeration.windows.dedup_by_key(|window| window.handle);

        Ok(ProcessWindowData
        {
            handle_count: enumeration.windows.len(),
            invisible_count: enumeration.windows.iter().filter(|window| !window.is_visible).count(),
            windows: enumeration.windows,
        })
    })();

    if let Err(error) = &result
    {
        let _ = error_handle::handle_std_error(error, "Querying process windows", print_errors);
    }

    result
}


/// Visits a root and all descendants, including target-owned children of other processes' windows; stored callback errors stop traversal and are reported by query_process_windows.
/// SAFETY: parameter is the live WindowEnumeration pointer supplied by the public helper. No Rust reference to it spans the nested synchronous EnumChildWindows call, whose return value is documented as unused.
unsafe extern "system" fn enumerate_window_tree(window: HWND, parameter: LPARAM) -> BOOL
{
    if unsafe { collect_process_window(window, parameter) } == 0
    {
        return 0;
    }

    unsafe
    {
        EnumChildWindows(window, Some(collect_process_window), parameter);
    }

    let enumeration = unsafe
    {
        &*(parameter as *const WindowEnumeration)
    };

    i32::from(enumeration.error.is_none())
}


/// Filters one window by owner PID and appends its visibility snapshot; destroyed windows are skipped, and allocation failures are stored for the public helper to report.
/// SAFETY: The synchronous caller supplies a valid, exclusively accessible WindowEnumeration pointer. Reservation precedes push so allocation failure cannot unwind across the native callback boundary.
unsafe extern "system" fn collect_process_window(window: HWND, parameter: LPARAM) -> BOOL
{
    let enumeration = unsafe
    {
        &mut *(parameter as *mut WindowEnumeration)
    };

    if enumeration.error.is_some()
    {
        return 0;
    }

    let mut process_id = 0;
    let (is_visible, thread_id) = unsafe
    {
        let is_visible = IsWindowVisible(window) != 0;
        (is_visible, GetWindowThreadProcessId(window, &mut process_id))
    };

    if thread_id == 0 || process_id != enumeration.process_id
    {
        return 1;
    }

    if let Err(error) = enumeration.windows.try_reserve(1)
    {
        enumeration.error = Some(io::Error::new(io::ErrorKind::OutOfMemory, error));
        return 0;
    }

    enumeration.windows.push(WindowData
    {
        handle: window as usize,
        thread_id,
        is_visible,
    });

    1
}
