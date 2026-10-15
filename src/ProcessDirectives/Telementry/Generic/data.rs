use std::io;
use std::os::windows::io::BorrowedHandle;
use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

#[path = "helpers.rs"]
pub mod helpers;

pub use helpers::ProcessProtection;
use helpers::{query_enabled_process_privileges, query_object_basic_information, query_process_basic_information, query_process_protection};

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


/// A complete owned record containing every helper's collected data, suitable for retaining after the handle closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessData
{
    pub object: ObjectData,
    pub process: ProcessBasicData,
    pub protection: ProcessProtection,
    pub enabled_privileges: Vec<String>,
}


/// Collects all four native helper results from a borrowed process handle and returns one owned record, or the first query failure; print_errors controls helper reporting.
pub fn collect_process_data(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<ProcessData>
{
    let object = query_object_basic_information(handle, print_errors)?;
    let process = query_process_basic_information(handle, print_errors)?;
    let protection = query_process_protection(handle, print_errors)?;
    let enabled_privileges = query_enabled_process_privileges(handle, print_errors)?;

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
    })
}


#[cfg(test)]
mod tests
{
    use super::*;
    use crate::error_handle::NtStatusError;
    use crate::process_handle_tests::open_process;
    use std::os::windows::io::AsHandle;
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, STATUS_ACCESS_DENIED, STATUS_PENDING};
    use windows_sys::Win32::System::Threading::{PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ};


    /// Confirms complete records remain usable after closing their source handle and sharing them across threads.
    #[test]
    fn collected_data_outlives_handle_and_can_be_shared()
    {
        for desired_access in [PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION]
        {
            let process_id = std::process::id();
            let handle = open_process(process_id, desired_access, false).unwrap();
            let data = Arc::new(collect_process_data(handle.as_handle(), false).unwrap());
            drop(handle);

            let worker_data = Arc::clone(&data);
            let retained = std::thread::spawn(move || worker_data).join().unwrap();

            assert!(Arc::ptr_eq(&data, &retained));
            assert_eq!(retained.process.process_id, process_id as usize);
            assert_eq!(retained.process.exit_status, STATUS_PENDING);
            assert_ne!(retained.process.peb_base_address, 0);
            assert_eq!(retained.object.granted_access & desired_access, desired_access);
            assert!(retained.object.handle_count >= 1);
        }
    }


    /// Confirms failed collection retains the original native query error instead of returning a partial or default record.
    #[test]
    fn collection_preserves_native_failure_without_a_record()
    {
        let handle = open_process(std::process::id(), PROCESS_VM_READ, false).unwrap();
        let error = collect_process_data(handle.as_handle(), false).unwrap_err();
        let native_error = error.get_ref().and_then(|error| error.downcast_ref::<NtStatusError>()).unwrap();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(native_error.status, STATUS_ACCESS_DENIED);
        assert_eq!(native_error.win32_code, ERROR_ACCESS_DENIED);
    }
}
