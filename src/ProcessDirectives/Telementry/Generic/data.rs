use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io;
use std::os::windows::io::BorrowedHandle;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

#[path = "handle_objects.rs"]
pub mod handle_objects;

#[path = "helpers.rs"]
pub mod helpers;

#[path = "window_objects.rs"]
pub mod window_objects;

pub use helpers::ProcessProtection;
pub use window_objects::ProcessWindowData;
use handle_objects::query_process_handle_type_counts;
use helpers::{query_enabled_process_privileges, query_object_basic_information, query_process_basic_information, query_process_parameters, query_process_protection};
use window_objects::query_process_windows;

/// Owned native object information, retaining reserved values without interpreting them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectData
{
    pub attributes: u32,
    pub granted_access: PROCESS_ACCESS_RIGHTS,
    pub handle_count: u32,
    pub pointer_count: u32,
    pub reserved: [u32; 10],
}


/// Owned process metadata with native-width identifiers and an opaque numeric PEB address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessBasicData
{
    pub exit_status: NTSTATUS,
    pub peb_base_address: usize,
    pub affinity_mask: usize,
    pub base_priority: i32,
    pub process_id: usize,
    pub parent_process_id: usize,
}


/// An owned record containing all seven query results, suitable for retaining after the handle closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessData
{
    pub object: ObjectData,
    pub process: ProcessBasicData,
    pub protection: ProcessProtection,
    pub enabled_privileges: Vec<String>,
    pub handle_type_counts: BTreeMap<String, usize>,
    pub current_directory: PathBuf,
    pub command_line: OsString,
    pub window_objects: ProcessWindowData,
}


/// Collects all seven helper results from a borrowed process handle with PROCESS_QUERY_INFORMATION and PROCESS_VM_READ; returns one owned record or the first failure, with print_errors controlling reporting.
pub fn collect_process_data(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<ProcessData>
{
    let object = query_object_basic_information(handle, print_errors)?;
    let process = query_process_basic_information(handle, print_errors)?;
    let protection = query_process_protection(handle, print_errors)?;
    let enabled_privileges = query_enabled_process_privileges(handle, print_errors)?;
    let handle_type_counts = query_process_handle_type_counts(handle, print_errors)?;
    let parameters = query_process_parameters(handle, print_errors)?;
    let window_objects = query_process_windows(handle, print_errors)?;

    Ok(ProcessData
    {
        object: ObjectData
        {
            attributes: object.Attributes,
            granted_access: object.GrantedAccess,
            handle_count: object.HandleCount,
            pointer_count: object.PointerCount,
            reserved: object.Reserved,
        },
        process: ProcessBasicData
        {
            exit_status: process.ExitStatus,
            peb_base_address: process.PebBaseAddress as usize,
            affinity_mask: process.AffinityMask,
            base_priority: process.BasePriority,
            process_id: process.UniqueProcessId,
            parent_process_id: process.InheritedFromUniqueProcessId,
        },
        protection,
        enabled_privileges,
        handle_type_counts,
        current_directory: parameters.current_directory,
        command_line: parameters.command_line,
        window_objects,
    })
}
