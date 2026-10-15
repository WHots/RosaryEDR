use std::io::ErrorKind;
use windows_sys::Win32::Foundation::{NTSTATUS, STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_ALERTED, STATUS_BREAKPOINT, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL, STATUS_CANCELLED, STATUS_CONFLICTING_ADDRESSES, STATUS_DATATYPE_MISALIGNMENT, STATUS_DLL_NOT_FOUND, STATUS_END_OF_FILE, STATUS_ENTRYPOINT_NOT_FOUND, STATUS_GUARD_PAGE_VIOLATION, STATUS_HANDLE_NOT_CLOSABLE, STATUS_ILLEGAL_INSTRUCTION, STATUS_IMAGE_NOT_AT_BASE, STATUS_INFO_LENGTH_MISMATCH, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_ADDRESS, STATUS_INVALID_CID, STATUS_INVALID_HANDLE, STATUS_INVALID_IMAGE_FORMAT, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PAGE_PROTECTION, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_MIX, STATUS_IN_PAGE_ERROR, STATUS_MEMORY_NOT_ALLOCATED, STATUS_NOT_FOUND, STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED, STATUS_NO_MEMORY, STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NO_TOKEN, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_INVALID, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_INVALID, STATUS_OBJECT_PATH_NOT_FOUND, STATUS_OBJECT_TYPE_MISMATCH, STATUS_PARTIAL_COPY, STATUS_PENDING, STATUS_PRIVILEGE_NOT_HELD, STATUS_PROCESS_IS_TERMINATING, STATUS_SHARING_VIOLATION, STATUS_SINGLE_STEP, STATUS_SUCCESS, STATUS_THREAD_IS_TERMINATING, STATUS_TIMEOUT, STATUS_UNSUCCESSFUL, STATUS_USER_APC};

/// Type-to-description map for all 39 stable I/O error kinds in Rust 1.99.
pub const IO_ERROR_DESCRIPTIONS: &[(ErrorKind, &str)] = &[
    (ErrorKind::NotFound, "The requested resource could not be found."),
    (ErrorKind::PermissionDenied, "The operation requires access permissions that were not granted."),
    (ErrorKind::ConnectionRefused, "The remote endpoint rejected the connection."),
    (ErrorKind::ConnectionReset, "The connection was reset by its peer."),
    (ErrorKind::HostUnreachable, "The destination host cannot be reached."),
    (ErrorKind::NetworkUnreachable, "The destination network cannot be reached."),
    (ErrorKind::ConnectionAborted, "The connection ended before the operation completed."),
    (ErrorKind::NotConnected, "The operation requires an established connection."),
    (ErrorKind::AddrInUse, "The requested address is already occupied."),
    (ErrorKind::AddrNotAvailable, "The requested address is unavailable on this system."),
    (ErrorKind::NetworkDown, "The network is currently unavailable."),
    (ErrorKind::BrokenPipe, "The pipe or connection was closed during an operation."),
    (ErrorKind::AlreadyExists, "The requested resource already exists."),
    (ErrorKind::WouldBlock, "The nonblocking operation cannot complete immediately."),
    (ErrorKind::NotADirectory, "A path component must be a directory."),
    (ErrorKind::IsADirectory, "The operation requires a file rather than a directory."),
    (ErrorKind::DirectoryNotEmpty, "The directory still contains entries."),
    (ErrorKind::ReadOnlyFilesystem, "The filesystem does not permit writes."),
    (ErrorKind::StaleNetworkFileHandle, "The remote file handle is no longer valid."),
    (ErrorKind::InvalidInput, "One or more operation parameters are invalid."),
    (ErrorKind::InvalidData, "The input data does not have the required format."),
    (ErrorKind::TimedOut, "The operation exceeded its time limit."),
    (ErrorKind::WriteZero, "A write made no progress before all data was written."),
    (ErrorKind::StorageFull, "The storage device has no remaining space."),
    (ErrorKind::NotSeekable, "The resource does not support seeking."),
    (ErrorKind::QuotaExceeded, "The operation exceeded an assigned resource quota."),
    (ErrorKind::FileTooLarge, "The file exceeds the permitted size."),
    (ErrorKind::ResourceBusy, "The resource is currently in use."),
    (ErrorKind::ExecutableFileBusy, "The executable is in use and cannot be modified."),
    (ErrorKind::Deadlock, "The requested lock would cause a deadlock."),
    (ErrorKind::CrossesDevices, "The operation cannot span different devices."),
    (ErrorKind::TooManyLinks, "The filesystem link limit has been reached."),
    (ErrorKind::InvalidFilename, "The filename is invalid or exceeds a name limit."),
    (ErrorKind::ArgumentListTooLong, "The process argument list exceeds a system limit."),
    (ErrorKind::Interrupted, "The operation was interrupted before completion."),
    (ErrorKind::Unsupported, "The requested operation is not supported."),
    (ErrorKind::UnexpectedEof, "The input ended before the required data was read."),
    (ErrorKind::OutOfMemory, "The operation could not allocate the required memory."),
    (ErrorKind::Other, "A custom I/O error occurred."),
];


/// Native code, symbolic name, and description for common process, memory, file, and security statuses; aliases use one canonical name.
pub const NTSTATUS_DESCRIPTIONS: &[(NTSTATUS, &str, &str)] = &[
    (STATUS_SUCCESS, "STATUS_SUCCESS", "The operation completed successfully."),
    (STATUS_USER_APC, "STATUS_USER_APC", "A user-mode asynchronous procedure call interrupted the wait."),
    (STATUS_ALERTED, "STATUS_ALERTED", "An alert interrupted the wait."),
    (STATUS_TIMEOUT, "STATUS_TIMEOUT", "The wait reached its time limit."),
    (STATUS_PENDING, "STATUS_PENDING", "The operation is waiting for completion."),
    (STATUS_IMAGE_NOT_AT_BASE, "STATUS_IMAGE_NOT_AT_BASE", "The image was loaded at an address other than its preferred base."),
    (STATUS_GUARD_PAGE_VIOLATION, "STATUS_GUARD_PAGE_VIOLATION", "An access triggered a guard-page exception."),
    (STATUS_DATATYPE_MISALIGNMENT, "STATUS_DATATYPE_MISALIGNMENT", "A memory access does not satisfy the required alignment."),
    (STATUS_BREAKPOINT, "STATUS_BREAKPOINT", "Execution encountered a breakpoint."),
    (STATUS_SINGLE_STEP, "STATUS_SINGLE_STEP", "Execution generated a single-step exception."),
    (STATUS_BUFFER_OVERFLOW, "STATUS_BUFFER_OVERFLOW", "The output buffer could not hold all available data."),
    (STATUS_NO_MORE_FILES, "STATUS_NO_MORE_FILES", "File enumeration has reached the last matching entry."),
    (STATUS_PARTIAL_COPY, "STATUS_PARTIAL_COPY", "Only part of the requested memory was copied."),
    (STATUS_UNSUCCESSFUL, "STATUS_UNSUCCESSFUL", "The operation failed without a more specific status."),
    (STATUS_NOT_IMPLEMENTED, "STATUS_NOT_IMPLEMENTED", "The requested system service is not implemented."),
    (STATUS_INVALID_INFO_CLASS, "STATUS_INVALID_INFO_CLASS", "The requested information class is invalid for this operation."),
    (STATUS_INFO_LENGTH_MISMATCH, "STATUS_INFO_LENGTH_MISMATCH", "The information buffer length does not match the required layout."),
    (STATUS_ACCESS_VIOLATION, "STATUS_ACCESS_VIOLATION", "The operation attempted an invalid memory access."),
    (STATUS_IN_PAGE_ERROR, "STATUS_IN_PAGE_ERROR", "A required memory page could not be retrieved from storage."),
    (STATUS_INVALID_HANDLE, "STATUS_INVALID_HANDLE", "The supplied handle is invalid."),
    (STATUS_INVALID_CID, "STATUS_INVALID_CID", "The supplied process or thread identifier is invalid."),
    (STATUS_INVALID_PARAMETER, "STATUS_INVALID_PARAMETER", "An operation parameter is invalid."),
    (STATUS_NO_SUCH_FILE, "STATUS_NO_SUCH_FILE", "The requested file does not exist."),
    (STATUS_END_OF_FILE, "STATUS_END_OF_FILE", "The requested read reached the end of the file."),
    (STATUS_NO_MEMORY, "STATUS_NO_MEMORY", "The operation could not allocate the required virtual memory."),
    (STATUS_CONFLICTING_ADDRESSES, "STATUS_CONFLICTING_ADDRESSES", "The requested address range conflicts with an existing allocation."),
    (STATUS_ILLEGAL_INSTRUCTION, "STATUS_ILLEGAL_INSTRUCTION", "Execution encountered an invalid processor instruction."),
    (STATUS_ACCESS_DENIED, "STATUS_ACCESS_DENIED", "The requested access rights were denied."),
    (STATUS_BUFFER_TOO_SMALL, "STATUS_BUFFER_TOO_SMALL", "The supplied buffer is smaller than required."),
    (STATUS_OBJECT_TYPE_MISMATCH, "STATUS_OBJECT_TYPE_MISMATCH", "The object has a different type than the operation requires."),
    (STATUS_INVALID_PARAMETER_MIX, "STATUS_INVALID_PARAMETER_MIX", "The supplied combination of parameters is invalid."),
    (STATUS_OBJECT_NAME_INVALID, "STATUS_OBJECT_NAME_INVALID", "The object name is malformed."),
    (STATUS_OBJECT_NAME_NOT_FOUND, "STATUS_OBJECT_NAME_NOT_FOUND", "No object has the requested name."),
    (STATUS_OBJECT_NAME_COLLISION, "STATUS_OBJECT_NAME_COLLISION", "An object with the requested name already exists."),
    (STATUS_OBJECT_PATH_INVALID, "STATUS_OBJECT_PATH_INVALID", "The object path is invalid."),
    (STATUS_OBJECT_PATH_NOT_FOUND, "STATUS_OBJECT_PATH_NOT_FOUND", "A required component of the object path was not found."),
    (STATUS_SHARING_VIOLATION, "STATUS_SHARING_VIOLATION", "Existing file access conflicts with the requested sharing mode."),
    (STATUS_INVALID_PAGE_PROTECTION, "STATUS_INVALID_PAGE_PROTECTION", "The requested memory protection is invalid."),
    (STATUS_THREAD_IS_TERMINATING, "STATUS_THREAD_IS_TERMINATING", "The target thread is terminating."),
    (STATUS_PRIVILEGE_NOT_HELD, "STATUS_PRIVILEGE_NOT_HELD", "The caller does not hold a required privilege."),
    (STATUS_INVALID_IMAGE_FORMAT, "STATUS_INVALID_IMAGE_FORMAT", "The executable image has an invalid or incompatible format."),
    (STATUS_NO_TOKEN, "STATUS_NO_TOKEN", "No token is available for the requested operation."),
    (STATUS_INSUFFICIENT_RESOURCES, "STATUS_INSUFFICIENT_RESOURCES", "The system lacks resources needed to complete the operation."),
    (STATUS_MEMORY_NOT_ALLOCATED, "STATUS_MEMORY_NOT_ALLOCATED", "The requested address range has not been allocated."),
    (STATUS_NOT_SUPPORTED, "STATUS_NOT_SUPPORTED", "The requested operation is unsupported."),
    (STATUS_PROCESS_IS_TERMINATING, "STATUS_PROCESS_IS_TERMINATING", "The target process is terminating."),
    (STATUS_CANCELLED, "STATUS_CANCELLED", "The operation was cancelled."),
    (STATUS_DLL_NOT_FOUND, "STATUS_DLL_NOT_FOUND", "A required dynamic-link library was not found."),
    (STATUS_ENTRYPOINT_NOT_FOUND, "STATUS_ENTRYPOINT_NOT_FOUND", "The required entry point was not found in the image."),
    (STATUS_INVALID_ADDRESS, "STATUS_INVALID_ADDRESS", "The requested address is invalid."),
    (STATUS_NOT_FOUND, "STATUS_NOT_FOUND", "The requested item was not found."),
    (STATUS_HANDLE_NOT_CLOSABLE, "STATUS_HANDLE_NOT_CLOSABLE", "The handle is protected from being closed."),
];


/// Maps an I/O error kind to a static description, including a fallback for unlisted kinds.
pub fn io_error_description(kind: ErrorKind) -> &'static str
{
    IO_ERROR_DESCRIPTIONS.iter().find(|(candidate, _)| *candidate == kind).map(|(_, description)| *description).unwrap_or("An unlisted I/O error category was reported.")
}


/// Returns the symbolic name and description for a mapped NTSTATUS, or None for an unlisted code.
pub fn ntstatus_details(status: NTSTATUS) -> Option<(&'static str, &'static str)>
{
    NTSTATUS_DESCRIPTIONS.iter().find(|(candidate, _, _)| *candidate == status).map(|(_, name, description)| (*name, *description))
}
