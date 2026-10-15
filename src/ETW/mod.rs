use crate::error_handle;
use std::io::{self, Write};
use std::mem::{offset_of, size_of};
use std::ptr::null;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use windows_sys::core::{BOOL, GUID, w};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_CANCELLED, ERROR_CTX_CLOSE_PENDING, ERROR_INVALID_HANDLE, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND};
use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT, SetConsoleCtrlHandler};
use windows_sys::Win32::System::Diagnostics::Etw::{CloseTrace, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, StartTraceW, TdhGetProperty, TdhGetPropertySize, CONTROLTRACE_HANDLE, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1, EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, PROCESSTRACE_HANDLE, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROPERTY_DATA_DESCRIPTOR, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID};

/// Windows' manifest-based provider for process lifecycle events.
const PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);

/// The one processing handle shared with the console control handler.
static ACTIVE_TRACE: AtomicU64 = AtomicU64::new(u64::MAX);

/// Records an explicit Ctrl+C or Ctrl+Break shutdown request.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// The owned monitor's console error policy, shared with ETW and console callbacks.
static PRINT_ERRORS: AtomicBool = AtomicBool::new(true);

/// Aligned ETW properties with writable space for the session name.
#[repr(C)]
struct TraceProperties
{
    properties: EVENT_TRACE_PROPERTIES,
    logger_name: [u16; 64],
}

/// Owns the controller session and the console handler registration.
struct TraceSession
{
    handle: CONTROLTRACE_HANDLE,
    properties: TraceProperties,
    console_handler_registered: bool,
    print_errors: bool,
}

/// Owned process-start fields decoded from the event payload.
#[derive(Debug)]
struct ProcessStart
{
    process_id: u32,
    parent_process_id: u32,
    image_name: String,
}


/// Monitors process starts until Ctrl+C; print_errors controls console error output, and failures remain an I/O result.
/// SAFETY: API buffers are initialized, aligned, and kept alive for each call; the guard owns only a successfully created session.
pub fn monitor_process_starts(print_errors: bool) -> io::Result<()>
{
    let mut properties = TraceProperties
    {
        properties: EVENT_TRACE_PROPERTIES::default(),
        logger_name: [0; 64],
    };

    properties.properties.Wnode.BufferSize = size_of::<TraceProperties>() as u32;
    properties.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.properties.Wnode.ClientContext = 1;
    properties.properties.BufferSize = 64;
    properties.properties.MinimumBuffers = 4;
    properties.properties.MaximumBuffers = 64;
    properties.properties.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
    properties.properties.FlushTimer = 1;
    properties.properties.LoggerNameOffset = offset_of!(TraceProperties, logger_name) as u32;

    let mut handle = CONTROLTRACE_HANDLE::default();
    let status = unsafe
    {
        StartTraceW(&mut handle, w!("RosaryEDR-ProcessStart"), &mut properties.properties)
    };

    if status == ERROR_ACCESS_DENIED
    {
        return Err(error_handle::handle_win32_error(status, "StartTraceW (run from an Administrator PowerShell or an account permitted to control ETW sessions)", print_errors));
    }

    if status == ERROR_ALREADY_EXISTS
    {
        return Err(error_handle::handle_win32_error(status, "StartTraceW (close the other RosaryEDR monitor or stop its orphaned session before restarting)", print_errors));
    }

    if status != ERROR_SUCCESS
    {
        return Err(error_handle::handle_win32_error(status, "StartTraceW", print_errors));
    }

    let mut session = TraceSession
    {
        handle,
        properties,
        console_handler_registered: false,
        print_errors,
    };

    STOP_REQUESTED.store(false, Ordering::Release);
    PRINT_ERRORS.store(print_errors, Ordering::Release);

    let mut logfile = EVENT_TRACE_LOGFILEW
    {
        LoggerName: w!("RosaryEDR-ProcessStart").cast_mut(),
        Anonymous1: EVENT_TRACE_LOGFILEW_0
        {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: EVENT_TRACE_LOGFILEW_1
        {
            EventRecordCallback: Some(process_start_callback),
        },
        ..Default::default()
    };

    let consumer = unsafe
    {
        OpenTraceW(&mut logfile)
    };

    if consumer.Value == u64::MAX
    {
        return Err(error_handle::handle_last_error("OpenTraceW", print_errors));
    }

    ACTIVE_TRACE.store(consumer.Value, Ordering::Release);

    let registered = unsafe
    {
        SetConsoleCtrlHandler(Some(console_control), 1)
    };

    if registered == 0
    {
        return Err(error_handle::handle_last_error("SetConsoleCtrlHandler", print_errors));
    }

    session.console_handler_registered = true;

    let status = unsafe
    {
        EnableTraceEx2(session.handle, &PROCESS_PROVIDER, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION as u8, 0x10, 0, 1000, null())
    };

    if status != ERROR_SUCCESS
    {
        return Err(error_handle::handle_win32_error(status, "EnableTraceEx2", print_errors));
    }

    if STOP_REQUESTED.load(Ordering::Acquire)
    {
        return Ok(());
    }

    if let Err(error) = writeln!(io::stdout().lock(), "Listening for process starts. ETW session: RosaryEDR-ProcessStart. Press Ctrl+C to stop.")
    {
        let _ = error_handle::handle_std_error(&error, "Could not print the ETW startup status", print_errors);
        return Err(error);
    }

    let status = unsafe
    {
        ProcessTrace(&consumer, 1, null(), null())
    };

    if status == ERROR_SUCCESS || (STOP_REQUESTED.load(Ordering::Acquire) && (status == ERROR_CANCELLED || status == ERROR_INVALID_HANDLE))
    {
        return Ok(());
    }

    Err(error_handle::handle_win32_error(status, "ProcessTrace", print_errors))
}


/// Releases the owned session and consumer; shutdown errors and loss counters go to stderr.
/// SAFETY: Only the atomic handle's owner closes it; the properties allocation remains valid until ControlTraceW returns.
impl Drop for TraceSession
{
    fn drop(&mut self)
    {
        if self.console_handler_registered
        {
            let removed = unsafe
            {
                SetConsoleCtrlHandler(Some(console_control), 0)
            };

            if removed == 0
            {
                let _ = error_handle::handle_last_error("Could not remove the console control handler", self.print_errors);
            }
        }

        let consumer = ACTIVE_TRACE.swap(u64::MAX, Ordering::AcqRel);

        if consumer != u64::MAX
        {
            let status = unsafe
            {
                CloseTrace(PROCESSTRACE_HANDLE { Value: consumer })
            };

            if status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING
            {
                let _ = error_handle::handle_win32_error(status, "CloseTrace", self.print_errors);
            }
        }

        let status = unsafe
        {
            ControlTraceW(self.handle, null(), &mut self.properties.properties, EVENT_TRACE_CONTROL_STOP)
        };

        if status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND
        {
            let _ = error_handle::handle_win32_error(status, "Could not stop the RosaryEDR ETW session", self.print_errors);
        }

        if self.print_errors && status == ERROR_SUCCESS && (self.properties.properties.EventsLost != 0 || self.properties.properties.RealTimeBuffersLost != 0)
        {
            let error = io::Error::other(format!("ETW lost {} events and {} real-time buffers during monitoring.", self.properties.properties.EventsLost, self.properties.properties.RealTimeBuffersLost));
            let _ = error_handle::handle_std_error(&error, "ETW event loss", self.print_errors);
        }
    }
}


/// Handles Ctrl+C/Break by closing the active consumer; returns whether the signal was handled.
/// SAFETY: CloseTrace accepts the live OpenTraceW handle transferred atomically from the monitor.
unsafe extern "system" fn console_control(control_type: u32) -> BOOL
{
    if control_type != CTRL_C_EVENT && control_type != CTRL_BREAK_EVENT
    {
        return 0;
    }

    STOP_REQUESTED.store(true, Ordering::Release);
    let consumer = ACTIVE_TRACE.swap(u64::MAX, Ordering::AcqRel);

    if consumer != u64::MAX
    {
        let status = unsafe
        {
            CloseTrace(PROCESSTRACE_HANDLE { Value: consumer })
        };

        if status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING
        {
            let _ = error_handle::handle_win32_error(status, "Could not close the ETW consumer on Ctrl+C", PRINT_ERRORS.load(Ordering::Acquire));
        }
    }

    1
}


/// Reports only this provider's ProcessStart events; ETW owns the supplied record until this callback returns.
/// SAFETY: ETW supplies valid record and payload pointers for the callback duration; no pointer is retained.
unsafe extern "system" fn process_start_callback(record: *mut EVENT_RECORD)
{
    let Some(record) = (unsafe { record.as_ref() }) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "ETW supplied a null event record.");
        let _ = error_handle::handle_std_error(&error, "Process-start callback", PRINT_ERRORS.load(Ordering::Acquire));
        return;
    };

    let provider = &record.EventHeader.ProviderId;

    if record.EventHeader.EventDescriptor.Id != 1 || provider.data1 != PROCESS_PROVIDER.data1 || provider.data2 != PROCESS_PROVIDER.data2 || provider.data3 != PROCESS_PROVIDER.data3 || provider.data4 != PROCESS_PROVIDER.data4
    {
        return;
    }

    let event = unsafe
    {
        decode_process_start(record)
    };

    match event
    {
        Ok(event) =>
        {
            if let Err(error) = writeln!(io::stdout().lock(), "Process started: PID={} ParentPID={} Image={}", event.process_id, event.parent_process_id, event.image_name.escape_debug())
            {
                let _ = error_handle::handle_std_error(&error, "Could not print the process-start event", PRINT_ERRORS.load(Ordering::Acquire));
            }
        }

        Err(error) =>
        {
            let _ = error_handle::handle_std_error(&error, &format!("Could not decode process-start event version {}", record.EventHeader.EventDescriptor.Version), PRINT_ERRORS.load(Ordering::Acquire));
        }
    }
}


/// Decodes payload fields by manifest property name and returns owned process details or a decoding error.
/// SAFETY: The caller must supply a valid ETW record and backing payload; TDH receives live descriptors and correctly sized writable buffers.
unsafe fn decode_process_start(record: &EVENT_RECORD) -> io::Result<ProcessStart>
{
    if record.UserData.is_null() || record.UserDataLength == 0
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "The process-start event has no payload."));
    }

    let mut identifiers = [[0_u8; 4]; 2];

    for (name, buffer) in [w!("ProcessID"), w!("ParentProcessID")].into_iter().zip(identifiers.iter_mut())
    {
        let property = PROPERTY_DATA_DESCRIPTOR
        {
            PropertyName: name as u64,
            ArrayIndex: u32::MAX,
            Reserved: 0,
        };

        let status = unsafe
        {
            TdhGetProperty(record, 0, null(), 1, &property, buffer.len() as u32, buffer.as_mut_ptr())
        };

        if status != ERROR_SUCCESS
        {
            return Err(error_handle::handle_win32_error(status, "TdhGetProperty (process identifier)", false));
        }
    }

    let property = PROPERTY_DATA_DESCRIPTOR
    {
        PropertyName: w!("ImageName") as u64,
        ArrayIndex: u32::MAX,
        Reserved: 0,
    };

    let mut byte_count = 0;
    let status = unsafe
    {
        TdhGetPropertySize(record, 0, null(), 1, &property, &mut byte_count)
    };

    if status != ERROR_SUCCESS
    {
        return Err(error_handle::handle_win32_error(status, "TdhGetPropertySize (ImageName)", false));
    }

    if byte_count < 2 || byte_count % 2 != 0 || byte_count > u32::from(record.UserDataLength)
    {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ImageName has an invalid UTF-16 buffer size."));
    }

    let mut image_name = vec![0_u16; byte_count as usize / 2];
    let status = unsafe
    {
        TdhGetProperty(record, 0, null(), 1, &property, byte_count, image_name.as_mut_ptr().cast())
    };

    if status != ERROR_SUCCESS
    {
        return Err(error_handle::handle_win32_error(status, "TdhGetProperty (ImageName)", false));
    }

    let image_end = image_name.iter().position(|&character| character == 0).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "ImageName is not null-terminated."))?;

    Ok(ProcessStart
    {
        process_id: u32::from_le_bytes(identifiers[0]),
        parent_process_id: u32::from_le_bytes(identifiers[1]),
        image_name: String::from_utf16_lossy(&image_name[..image_end]),
    })
}


#[cfg(test)]
mod tests
{
    use super::*;
    use windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER_FLAG_64_BIT_HEADER;


    /// Confirms payload identifiers are used when the event header names a different process.
    /// SAFETY: The record references this test's live, correctly sized version-zero payload.
    #[test]
    fn decodes_payload_ids_instead_of_header_pid()
    {
        let image = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe";
        let mut payload = Vec::from(1234_u32.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&5678_u32.to_le_bytes());
        payload.extend_from_slice(&1_u32.to_le_bytes());

        for character in image.encode_utf16().chain([0])
        {
            payload.extend_from_slice(&character.to_le_bytes());
        }

        let record = process_start_record(&mut payload, 0);
        let event = unsafe
        {
            decode_process_start(&record)
        }.expect("TDH should decode the installed version-zero manifest");

        assert_eq!(event.process_id, 1234);
        assert_ne!(event.process_id, record.EventHeader.ProcessId);
        assert_eq!(event.parent_process_id, 5678);
        assert_eq!(event.image_name, image);
    }


    /// Confirms TDH handles the newer flags field and preserves Unicode image names.
    /// SAFETY: The record references this test's live version-one payload, including its UTF-16 terminator.
    #[test]
    fn decodes_version_one_unicode_image()
    {
        let image = r"\Device\HarddiskVolume3\分析\🦀.exe";
        let mut payload = Vec::from(4321_u32.to_le_bytes());
        payload.extend_from_slice(&0_u64.to_le_bytes());
        payload.extend_from_slice(&8765_u32.to_le_bytes());
        payload.extend_from_slice(&2_u32.to_le_bytes());
        payload.extend_from_slice(&0x01020304_u32.to_le_bytes());

        for character in image.encode_utf16().chain([0])
        {
            payload.extend_from_slice(&character.to_le_bytes());
        }

        let record = process_start_record(&mut payload, 1);
        let event = unsafe
        {
            decode_process_start(&record)
        }.expect("TDH should decode the installed version-one manifest");

        assert_eq!(event.process_id, 4321);
        assert_eq!(event.parent_process_id, 8765);
        assert_eq!(event.image_name, image);
    }


    /// Confirms missing payloads are rejected before passing a null buffer to TDH.
    /// SAFETY: The decoder rejects this empty record before accessing its payload pointer.
    #[test]
    fn rejects_missing_payload()
    {
        let record = EVENT_RECORD::default();
        let error = unsafe
        {
            decode_process_start(&record)
        }.expect_err("An empty event must not decode successfully");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }


    /// Confirms truncated event data returns an error instead of fabricated process details.
    /// SAFETY: The record references the live truncated allocation with its actual byte length.
    #[test]
    fn rejects_truncated_payload()
    {
        let mut payload = Vec::from(1234_u32.to_le_bytes());
        let record = process_start_record(&mut payload, 0);
        let event = unsafe
        {
            decode_process_start(&record)
        };

        assert!(event.is_err());
    }


    /// Builds a manifest event around a borrowed fixture payload; the caller keeps the payload alive.
    fn process_start_record(payload: &mut [u8], version: u8) -> EVENT_RECORD
    {
        let mut record = EVENT_RECORD::default();
        record.EventHeader.Size = size_of::<windows_sys::Win32::System::Diagnostics::Etw::EVENT_HEADER>() as u16;
        record.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER as u16;
        record.EventHeader.ProviderId = PROCESS_PROVIDER;
        record.EventHeader.ProcessId = 9000;
        record.EventHeader.EventDescriptor.Id = 1;
        record.EventHeader.EventDescriptor.Version = version;
        record.EventHeader.EventDescriptor.Level = TRACE_LEVEL_INFORMATION as u8;
        record.EventHeader.EventDescriptor.Opcode = 1;
        record.EventHeader.EventDescriptor.Keyword = 0x8000000000000010;
        record.UserDataLength = u16::try_from(payload.len()).expect("Fixture payload fits in an ETW record");
        record.UserData = payload.as_mut_ptr().cast();
        record
    }
}
