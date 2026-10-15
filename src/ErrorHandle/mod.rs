use std::borrow::Cow;
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{GetLastError, LocalFree, RtlNtStatusToDosError, SetLastError, NTSTATUS};
use windows_sys::core::{w, PCWSTR};
use windows_sys::Win32::System::Diagnostics::Debug::{FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_HMODULE, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

pub mod error_map;

/// Native FormatMessage flag for suppressing soft line breaks, absent from these generated bindings.
const FORMAT_MESSAGE_MAX_WIDTH_MASK: u32 = 0xFF;

/// A native failure retaining the original NTSTATUS and its equivalent Win32 description code.
#[derive(Debug)]
pub struct NtStatusError
{
    pub status: NTSTATUS,
    pub win32_code: u32,
}


/// Prints a Rust error and its causes to stderr when enabled; returns only the console write result.
/// SAFETY: GetLastError and SetLastError access only the calling thread's error slot, which is preserved around reporting.
pub fn handle_std_error(error: &(dyn Error + 'static), context: &str, print_to_console: bool) -> io::Result<()>
{
    if !print_to_console
    {
        return Ok(());
    }

    let saved_error = unsafe
    {
        GetLastError()
    };

    let result = write_error(error, context, &mut io::stderr().lock());

    unsafe
    {
        SetLastError(saved_error);
    }

    result
}


/// Handles an explicit failed Win32 status, optionally prints it, and returns an I/O error preserving its raw code.
pub fn handle_win32_error(code: u32, context: &str, print_to_console: bool) -> io::Error
{
    let error = io::Error::from_raw_os_error(code as i32);
    let _ = handle_std_error(&error, context, print_to_console);
    error
}


/// Captures GetLastError immediately after a failed API call, optionally prints it, and returns the captured I/O error.
/// SAFETY: GetLastError has no pointer or handle preconditions and reads only the calling thread's error slot.
pub fn handle_last_error(context: &str, print_to_console: bool) -> io::Error
{
    let code = unsafe
    {
        GetLastError()
    };

    handle_win32_error(code, context, print_to_console)
}


/// Handles a failed NTSTATUS without consulting GetLastError; returns a classified I/O error containing the original native status.
/// SAFETY: RtlNtStatusToDosError accepts the captured status value and does not access caller-supplied memory.
#[allow(dead_code, reason = "The standalone process-handle module currently uses this handler only in test builds.")]
pub fn handle_ntstatus_error(status: NTSTATUS, context: &str, print_to_console: bool) -> io::Error
{
    let win32_code = unsafe
    {
        RtlNtStatusToDosError(status)
    };

    let kind = io::Error::from_raw_os_error(win32_code as i32).kind();
    let error = io::Error::new(kind, NtStatusError { status, win32_code });
    let _ = handle_std_error(&error, context, print_to_console);
    error
}


/// Looks up a Win32 code in the native system message catalog and returns its description or a numeric fallback.
pub fn win32_description(code: u32) -> String
{
    native_description(code, None).unwrap_or_else(|| format!("No system description is registered for Win32 error {code} (0x{code:08X})."))
}


/// Formats an original NTSTATUS with a mapped name/description or an ntdll catalog fallback, retaining its Win32 code.
impl fmt::Display for NtStatusError
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        let (name, description) = match error_map::ntstatus_details(self.status)
        {
            Some((name, description)) => (name, Cow::Borrowed(description)),
            None => ("unlisted status", Cow::Owned(native_description(self.status as u32, Some(w!("ntdll.dll"))).unwrap_or_else(|| format!("No native description is registered for NTSTATUS 0x{:08X}.", self.status as u32)))),
        };

        write!(formatter, "NTSTATUS 0x{:08X} ({name}, Win32 {}): {description}", self.status as u32, self.win32_code)
    }
}


impl Error for NtStatusError
{
}


/// Returns a catalog message for a code, using either system messages or a loaded module, and preserves GetLastError.
/// SAFETY: Module names are static terminated UTF-16 strings; ntdll remains loaded for this process's lifetime. FormatMessageW's returned count bounds the buffer read, LocalFree releases it once, and borrowed module handles are never freed.
fn native_description(code: u32, module_name: Option<PCWSTR>) -> Option<String>
{
    let saved_error = unsafe
    {
        GetLastError()
    };

    let module = match module_name
    {
        Some(name) => unsafe
        {
            GetModuleHandleW(name)
        },
        None => null_mut(),
    };

    let source_flag = if module_name.is_some()
    {
        FORMAT_MESSAGE_FROM_HMODULE
    }
    else
    {
        FORMAT_MESSAGE_FROM_SYSTEM
    };

    let mut buffer = null_mut::<u16>();
    let length = if module_name.is_some() && module.is_null()
    {
        0
    }
    else
    {
        unsafe
        {
            FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | source_flag | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_MAX_WIDTH_MASK, module.cast(), code, 0, (&mut buffer as *mut *mut u16).cast(), 0, null())
        }
    };

    let description = if length != 0 && !buffer.is_null()
    {
        let message = unsafe
        {
            std::slice::from_raw_parts(buffer, length as usize)
        };

        Some(String::from_utf16_lossy(message).trim().to_owned())
    }
    else
    {
        None
    };

    if !buffer.is_null()
    {
        unsafe
        {
            LocalFree(buffer.cast());
        }
    }

    unsafe
    {
        SetLastError(saved_error);
    }

    description
}


/// Writes the error category, description, and up to 16 causes to the supplied writer; returns any write failure.
fn write_error(error: &(dyn Error + 'static), context: &str, output: &mut impl Write) -> io::Result<()>
{
    if let Some(io_error) = error.downcast_ref::<io::Error>()
    {
        let kind = io_error.kind();
        let kind_description = error_map::io_error_description(kind);

        if let Some(native_error) = io_error.get_ref().and_then(|error| error.downcast_ref::<NtStatusError>())
        {
            writeln!(output, "{context}: [{kind:?}] {kind_description} {native_error}")?;
        }
        else if let Some(code) = io_error.raw_os_error()
        {
            let code = code as u32;
            writeln!(output, "{context}: [Win32 {code} / 0x{code:08X}, {kind:?}] {kind_description} {}", win32_description(code))?;
        }
        else
        {
            writeln!(output, "{context}: [Rust I/O {kind:?}] {kind_description} {io_error}")?;
        }
    }
    else if let Some(native_error) = error.downcast_ref::<NtStatusError>()
    {
        writeln!(output, "{context}: [{native_error}]")?;
    }
    else
    {
        writeln!(output, "{context}: [Rust] {error}")?;
    }

    let mut source = error.source();

    for _ in 0..16
    {
        let Some(cause) = source else
        {
            return Ok(());
        };

        writeln!(output, "  Caused by: {cause}")?;
        source = cause.source();
    }

    if source.is_some()
    {
        writeln!(output, "  Additional error causes omitted.")?;
    }

    Ok(())
}


#[cfg(test)]
mod tests
{
    use super::*;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_MR_MID_NOT_FOUND, STATUS_ACCESS_DENIED, STATUS_INVALID_CID, STATUS_INVALID_PARAMETER_MIX, STATUS_STACK_OVERFLOW};

    /// Fails if a supposedly suppressed error is formatted.
    #[derive(Debug)]
    struct UnformattableError;


    impl fmt::Display for UnformattableError
    {
        fn fmt(&self, _formatter: &mut fmt::Formatter<'_>) -> fmt::Result
        {
            panic!("Suppression must not format the error");
        }
    }


    impl Error for UnformattableError
    {
    }


    /// Exercises cause handling with both a native nested error and a cyclic source.
    #[derive(Debug)]
    struct WrapperError
    {
        cause: Option<io::Error>,
    }


    impl fmt::Display for WrapperError
    {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result
        {
            formatter.write_str("The outer operation failed")
        }
    }


    impl Error for WrapperError
    {
        fn source(&self) -> Option<&(dyn Error + 'static)>
        {
            match &self.cause
            {
                Some(cause) => Some(cause),
                None => Some(self),
            }
        }
    }


    /// Confirms suppression bypasses formatting entirely, including arbitrary Rust error types.
    #[test]
    fn suppression_does_not_format_errors()
    {
        assert!(handle_std_error(&UnformattableError, "Suppressed operation", false).is_ok());
    }


    /// Confirms GetLastError is captured before any formatting and remains thread-local.
    /// SAFETY: The test sets and reads only its own thread's last-error value.
    #[test]
    fn captures_last_error_without_printing()
    {
        unsafe
        {
            SetLastError(ERROR_ACCESS_DENIED);
        }

        let error = handle_last_error("Failed Windows call", false);
        let last_error = unsafe
        {
            GetLastError()
        };

        assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(last_error, ERROR_ACCESS_DENIED);
    }


    /// Confirms NTSTATUS reporting preserves the source status and classifies its converted Win32 error.
    #[test]
    fn ntstatus_errors_preserve_original_status_and_classification()
    {
        let error = handle_ntstatus_error(STATUS_ACCESS_DENIED, "Native access check", false);
        let native_error = error.get_ref().and_then(|error| error.downcast_ref::<NtStatusError>()).unwrap();
        let mut output = Vec::new();
        write_error(&error, "Native access check", &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(native_error.status, STATUS_ACCESS_DENIED);
        assert_eq!(native_error.win32_code, ERROR_ACCESS_DENIED);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(output.contains("NTSTATUS 0xC0000022"));
        assert!(output.contains("STATUS_ACCESS_DENIED"));
        assert!(output.contains("The requested access rights were denied."));
        assert!(output.contains("Win32 5"));
        assert!(output.contains("PermissionDenied"));
    }


    /// Confirms an unrecognized NTSTATUS retains its original bits even when Windows has no conversion.
    #[test]
    fn unmapped_ntstatus_errors_retain_original_status()
    {
        let status = 0xCFFF0123_u32 as NTSTATUS;
        let error = handle_ntstatus_error(status, "Unmapped native status", false);
        let native_error = error.get_ref().and_then(|error| error.downcast_ref::<NtStatusError>()).unwrap();

        assert_eq!(native_error.status, status);
        assert_eq!(native_error.win32_code, ERROR_MR_MID_NOT_FOUND);
        assert!(error.to_string().contains("0xCFFF0123"));
        assert!(error.to_string().contains("No native description is registered for NTSTATUS 0xCFFF0123."));
    }


    /// Confirms different native failures remain distinguishable when both convert to the same Win32 code.
    #[test]
    fn ntstatus_map_distinguishes_failures_with_same_win32_code()
    {
        let invalid_client = handle_ntstatus_error(STATUS_INVALID_CID, "Opening process", false);
        let invalid_parameters = handle_ntstatus_error(STATUS_INVALID_PARAMETER_MIX, "Opening process", false);
        let client_message = invalid_client.to_string();
        let parameter_message = invalid_parameters.to_string();

        assert!(client_message.contains("Win32 87"));
        assert!(parameter_message.contains("Win32 87"));
        assert!(client_message.contains("STATUS_INVALID_CID"));
        assert!(client_message.contains("The supplied process or thread identifier is invalid."));
        assert!(parameter_message.contains("STATUS_INVALID_PARAMETER_MIX"));
        assert!(parameter_message.contains("The supplied combination of parameters is invalid."));
        assert_ne!(client_message, parameter_message);
    }


    /// Confirms statuses outside the static map use ntdll's own catalog without overwriting the thread's last error.
    /// SAFETY: The test sets and reads only its own thread's last-error value; ntdll is already loaded and is not freed.
    #[test]
    fn unlisted_ntstatus_uses_native_catalog_and_preserves_last_error()
    {
        assert!(error_map::ntstatus_details(STATUS_STACK_OVERFLOW).is_none());

        unsafe
        {
            SetLastError(ERROR_INVALID_PARAMETER);
        }

        let native_error = NtStatusError { status: STATUS_STACK_OVERFLOW, win32_code: 1001 };
        let message = native_error.to_string();
        let last_error = unsafe
        {
            GetLastError()
        };

        assert!(message.contains("NTSTATUS 0xC00000FD"));
        assert!(!message.contains("No native description is registered"));
        assert_eq!(last_error, ERROR_INVALID_PARAMETER);

        let unknown_error = NtStatusError { status: 0xCFFF0123_u32 as NTSTATUS, win32_code: ERROR_MR_MID_NOT_FOUND };
        let message = unknown_error.to_string();
        let last_error = unsafe
        {
            GetLastError()
        };

        assert!(message.contains("No native description is registered for NTSTATUS 0xCFFF0123."));
        assert_eq!(last_error, ERROR_INVALID_PARAMETER);
    }


    /// Confirms application-defined statuses retain their bits when Windows returns the same value as the converted code.
    #[test]
    fn application_ntstatus_conversion_keeps_both_codes()
    {
        let status = 0xE1234567_u32 as NTSTATUS;
        let error = handle_ntstatus_error(status, "Application-defined native status", false);
        let native_error = error.get_ref().and_then(|error| error.downcast_ref::<NtStatusError>()).unwrap();

        assert_eq!(native_error.status, status);
        assert_eq!(native_error.win32_code, status as u32);
    }


    /// Confirms native catalog lookup returns a description without overwriting the existing last-error value.
    /// SAFETY: The test sets and reads only its own thread's last-error value.
    #[test]
    fn native_lookup_preserves_last_error()
    {
        unsafe
        {
            SetLastError(ERROR_INVALID_PARAMETER);
        }

        let description = win32_description(ERROR_ACCESS_DENIED);
        let last_error = unsafe
        {
            GetLastError()
        };

        assert!(!description.is_empty());
        assert!(!description.starts_with("No system description"));
        assert_eq!(description, description.trim());
        assert_eq!(last_error, ERROR_INVALID_PARAMETER);
    }


    /// Confirms unmapped application errors retain all 32 code bits and have a useful fallback.
    #[test]
    fn unknown_win32_codes_keep_their_numeric_value()
    {
        let code = 0xE1234567_u32;
        let error = handle_win32_error(code, "Application-defined failure", false);
        let description = win32_description(code);

        assert_eq!(error.raw_os_error().map(|value| value as u32), Some(code));
        assert!(description.contains(&code.to_string()));
        assert!(description.contains("0xE1234567"));
    }


    /// Confirms Rust I/O reporting includes its category, context, and original custom message.
    #[test]
    fn rust_io_reporting_preserves_custom_details()
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "Invalid PE header");
        let mut output = Vec::new();
        write_error(&error, "Reading the image", &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Reading the image"));
        assert!(output.contains("Rust I/O InvalidData"));
        assert!(output.contains("Invalid PE header"));
    }


    /// Confirms a non-I/O standard library error is handled through the Error trait.
    #[test]
    fn reports_non_io_standard_errors()
    {
        let error = "invalid".parse::<u32>().unwrap_err();
        let mut output = Vec::new();
        write_error(&error, "Parsing a process ID", &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("[Rust]"));
        assert!(output.contains(&error.to_string()));
    }


    /// Confirms nested errors retain their original native message in the cause chain.
    #[test]
    fn reports_original_error_causes()
    {
        let cause = io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32);
        let cause_text = cause.to_string();
        let error = WrapperError { cause: Some(cause) };
        let mut output = Vec::new();
        write_error(&error, "Nested failure", &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.contains("Caused by:"));
        assert!(output.contains(&cause_text));
    }


    /// Confirms cyclic error chains terminate within the documented reporting bound.
    #[test]
    fn cyclic_causes_do_not_loop_forever()
    {
        let error = WrapperError { cause: None };
        let mut output = Vec::new();
        write_error(&error, "Cyclic failure", &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert_eq!(output.matches("Caused by:").count(), 16);
        assert!(output.contains("Additional error causes omitted."));
    }


    /// Confirms an output failure is returned without recursively attempting to report it.
    #[test]
    fn returns_console_writer_failures()
    {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "The destination closed");
        let mut output: &mut [u8] = &mut [];
        let write_error = write_error(&error, "Writing output", &mut output).unwrap_err();

        assert_eq!(write_error.kind(), io::ErrorKind::WriteZero);
    }
}
