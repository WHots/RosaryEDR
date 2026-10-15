use std::process::ExitCode;

#[path = "ETW/mod.rs"]
mod etw;

#[path = "ErrorHandle/mod.rs"]
mod error_handle;

#[cfg(test)]
#[path = "ProcessDirectives/imports.rs"]
mod process_imports;

#[cfg(test)]
#[allow(dead_code, reason = "The standalone process-handle component is intentionally not wired into the ETW flow.")]
#[path = "ProcessDirectives/handle.rs"]
mod process_handle_tests;

#[cfg(test)]
#[allow(dead_code, reason = "Generic telemetry helpers are compiled for validation but are intentionally not wired into the ETW flow.")]
#[path = "ProcessDirectives/Telementry/Generic/data.rs"]
mod process_telemetry_tests;

#[cfg(test)]
#[allow(dead_code, reason = "PE telemetry helpers are compiled for validation but are intentionally not wired into the ETW flow.")]
#[path = "ProcessDirectives/Telementry/PE/helpers.rs"]
mod process_pe_tests;



fn main() -> ExitCode
{
    match etw::monitor_process_starts(true)
    {
        Ok(()) => ExitCode::SUCCESS,

        Err(_) => ExitCode::FAILURE,
    }
}
