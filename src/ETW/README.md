# ETW process-start monitoring

[mod.rs](mod.rs) owns RosaryEDR's real-time Event Tracing for Windows (ETW)
controller session and event consumer. [src/main.rs](../main.rs) loads it as
`crate::etw` and calls `monitor_process_starts(true)`.

This Windows x64 component uses the existing `windows-sys` bindings. ETW's
controller/provider/consumer model is described in Microsoft's
[ETW overview](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).

## Public API

```rust
pub fn monitor_process_starts(print_errors: bool) -> std::io::Result<()>
```

The call blocks while consuming events. Ctrl+C or Ctrl+Break requests shutdown.
A normal shutdown returns `Ok(())`; startup or event-processing failures return
`Err(io::Error)`. The binary translates that result into its exit code.

`print_errors` controls error and event-loss reporting to stderr through
[ErrorHandle](../ErrorHandle/README.md). Passing `false` still returns failures
and still prints the startup message and successfully decoded process-start
events to stdout.

The fixed session name and process-wide atomic state support one active monitor
per process. The API is not designed for concurrent monitoring calls.

## Provider and session settings

| Setting | Configured value |
| --- | --- |
| Session name | `RosaryEDR-ProcessStart` |
| Provider | `Microsoft-Windows-Kernel-Process` |
| Provider GUID | `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716` |
| Enabled keyword | `0x10` (process events) |
| Enabled level | `TRACE_LEVEL_INFORMATION` |
| Accepted event ID | `1` (ProcessStart) |
| Session mode | `EVENT_TRACE_REAL_TIME_MODE \| EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` |
| Consumer mode | `PROCESS_TRACE_MODE_REAL_TIME \| PROCESS_TRACE_MODE_EVENT_RECORD` |
| Requested buffer size | 64 KiB |
| Requested buffer counts | Minimum 4, maximum 64 |
| Flush timer | 1 second |

The callback checks both the provider GUID and event ID before decoding.
Monitoring observes newly delivered process-start events; it does not enumerate
processes that were already running or collect process-exit events.

## Lifecycle and ownership

1. `StartTraceW` creates the named session. Failure returns immediately; an
   existing session is not adopted or stopped.
2. A private `TraceSession` guard takes ownership of the successfully created
   controller session.
3. `OpenTraceW` opens the real-time consumer, and `SetConsoleCtrlHandler`
   registers the shutdown callback.
4. `EnableTraceEx2` enables the process provider.
5. `ProcessTrace` dispatches records to the callback until consumption ends.
6. Dropping the guard unregisters the console handler, closes any remaining
   consumer, and stops the owned controller session with `ControlTraceW`.

The guard also releases acquired resources after later startup failures.
An atomic swap transfers the consumer handle to whichever shutdown path closes
it, preventing the console handler and guard from both closing that handle.
Ctrl+C and Ctrl+Break set the stop flag and close the consumer; the guard then
finishes session cleanup.

After an explicit stop request, `ERROR_CANCELLED` and `ERROR_INVALID_HANDLE`
from `ProcessTrace` are accepted as normal shutdown results.
Cleanup failures are reported when enabled; they do not replace the monitor's
return value because cleanup runs in `Drop`.

## Event decoding and output

A private `ProcessStart` record owns these decoded values:

| Field | Rust type | Payload property |
| --- | --- | --- |
| `process_id` | `u32` | `ProcessID` |
| `parent_process_id` | `u32` | `ParentProcessID` |
| `image_name` | `String` | `ImageName` |

The decoder uses [TdhGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhgetproperty)
with manifest property names instead of hard-coded payload offsets. PID and
parent PID come from the event payload; the event header PID is not used as
the new process PID.

For the image name, `TdhGetPropertySize` determines the required UTF-16 buffer
size. The decoder rejects missing payloads, sizes below two bytes, odd byte
counts, sizes larger than the payload, and missing null terminators. It converts
the string with `String::from_utf16_lossy`.

ETW owns the event record and its payload during the callback. No borrowed event
pointer is retained; the decoded values are owned. The callback prints:

```text
Process started: PID=1234 ParentPID=5678 Image=\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe
```

The image name is formatted with `escape_debug()`, so backslashes and control
characters are escaped. The provider's image path may use a Windows device path;
the monitor does not translate it into a drive-letter path.

The record type and decoder are private. The current public API prints events
and returns the monitoring result; it does not expose a record stream or invoke
the Generic/PE telemetry collectors.

## Run and stop

From the project root, use an Administrator PowerShell or an account permitted
to create the ETW session and enable the provider:

```powershell
cargo run
```

Start another application to generate process-start events. Press Ctrl+C or
Ctrl+Break in the monitor console to stop it.

If a previous monitor was forcibly terminated, first confirm that it is no
longer running. Then stop its orphaned session from an Administrator PowerShell:

```powershell
logman stop RosaryEDR-ProcessStart -ets
```

The normal shutdown path already stops its session.

## Errors and event loss

| Situation | Behavior |
| --- | --- |
| `StartTraceW` returns `ERROR_ACCESS_DENIED` | Returns an error with guidance about ETW permissions. |
| The session already exists | Returns `ERROR_ALREADY_EXISTS` with restart guidance. |
| A controller, consumer, or provider setup call fails | Returns the captured Win32 failure and cleans up owned resources. |
| The startup message cannot be written | Returns the output error and cleans up the session. |
| A record cannot be decoded or printed | Reports the failure when enabled, then continues monitoring. |
| `ProcessTrace` fails outside an accepted shutdown case | Returns its Win32 error. |
| Cleanup reports lost events or real-time buffers | Reports their nonzero counts to stderr when enabled. |

Callback errors do not propagate out of `ProcessTrace` through the module's
`io::Result`. A monitor that returns successfully may still have skipped
malformed records, encountered output failures, or lost events.

The callback decodes and prints synchronously. Slow output or a high event rate
can outpace consumption. Loss counters are checked after a successful session
stop; passing `false` suppresses that report as well as other diagnostics.

## Verification

Run the existing decoder tests from the project root:

```powershell
cargo test etw::tests
```

They exercise Windows' installed TDH manifest decoder with version-zero and
version-one payloads, payload identifiers that differ from the event header PID,
Unicode image names, and missing/truncated payloads.

These tests do not start a live session and do not require administrator
permissions. Live capture, console shutdown, and ETW session cleanup require
manual verification with the permissions described above.
