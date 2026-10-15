use crate::error_handle;
use crate::process_imports::process_apis;
use crate::process_telemetry_tests::helpers::query_process_basic_information;
use signatures::{contains_signature, MZ_SIGNATURE, PE_SIGNATURE};
use std::ffi::c_void;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, BorrowedHandle};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessWow64Information};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_HEADER, IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_OPTIONAL_HEADER32, IMAGE_OPTIONAL_HEADER64};
use windows_sys::Win32::System::SystemInformation::{IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386};

#[path = "signatures.rs"]
#[allow(dead_code, reason = "The signature catalog includes opcode entries available for future inspection callers.")]
pub mod signatures;

#[path = "sections.rs"]
pub mod sections;

/// ImageBaseAddress field offsets in the native x64 and WoW64 x86 PEB layouts.
const PEB64_IMAGE_BASE_OFFSET: usize = 0x10;
const PEB32_IMAGE_BASE_OFFSET: usize = 0x08;

/// Windows loader section-count limit, shared by COFF validation and bounded section-table reads.
const MAX_IMAGE_SECTIONS: usize = 96;

/// Numeric target addresses for the selected PEB and its reported main executable image, with the target's WoW64 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessPeAddress
{
    pub peb_base_address: usize,
    pub image_base_address: usize,
    pub is_wow64: bool,
}


/// Owned common optional-header fields for a PE32 or PE32+ image; these values describe the image layout and are not a native API buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessOptionalHeader
{
    pub magic: u16,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
}


/// Queries a borrowed process's appropriate PEB and verifies its reported main image's MZ/PE signatures; returns owned numeric addresses and optionally reports failures.
/// SAFETY: The initialized pointer-sized WoW64 result remains writable during the native call; target PEB addresses are passed to a bounded native memory read and never dereferenced locally.
pub fn query_process_pe_address(handle: BorrowedHandle<'_>, print_errors: bool) -> io::Result<ProcessPeAddress>
{
    let mut wow64_peb = 0_usize;
    let mut returned_length = 0;
    let size = size_of::<usize>() as u32;

    let status = unsafe
    {
        NtQueryInformationProcess(handle.as_raw_handle(), ProcessWow64Information, (&mut wow64_peb as *mut usize).cast(), size, &mut returned_length)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, "NtQueryInformationProcess(ProcessWow64Information)", print_errors));
    }

    if returned_length != size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("WoW64 information returned {returned_length} bytes; expected {size}."));
        let _ = error_handle::handle_std_error(&error, "Querying process PE address", print_errors);
        return Err(error);
    }

    let is_wow64 = wow64_peb != 0;
    let peb_base_address = if is_wow64
    {
        if wow64_peb > u32::MAX as usize
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, "The WoW64 PEB address exceeds the 32-bit address range.");
            let _ = error_handle::handle_std_error(&error, "Querying process PE address", print_errors);
            return Err(error);
        }

        wow64_peb
    }
    else
    {
        query_process_basic_information(handle, print_errors)?.PebBaseAddress as usize
    };

    if peb_base_address == 0
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The process query returned a null PEB address.");
        let _ = error_handle::handle_std_error(&error, "Querying process PE address", print_errors);
        return Err(error);
    }

    let image_base_address = read_image_base_address(handle, peb_base_address, is_wow64, print_errors)?;
    validate_process_pe_image(handle, image_base_address, print_errors)?;

    Ok(ProcessPeAddress
    {
        peb_base_address,
        image_base_address,
        is_wow64,
    })
}


/// Checks MZ and PE\0\0 at a borrowed process's image base and signed e_lfanew offset; returns the remote NT signature address or an optionally reported error, without validating later headers.
pub fn validate_process_pe_image(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool) -> io::Result<usize>
{
    if image_base_address == 0
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The image base address is null.");
        let _ = error_handle::handle_std_error(&error, "Validating process PE image", print_errors);

        return Err(error);
    }

    let mut dos_header = [0_u8; 64];

    read_process_bytes(handle, image_base_address, &mut dos_header, "NtReadVirtualMemory(DOS header)", print_errors)?;

    if !contains_signature(&dos_header[..MZ_SIGNATURE.len()], &MZ_SIGNATURE)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The image base does not contain the MZ signature.");
        let _ = error_handle::handle_std_error(&error, "Validating process PE image", print_errors);

        return Err(error);
    }

    let nt_offset = i32::from_le_bytes([dos_header[0x3C], dos_header[0x3D], dos_header[0x3E], dos_header[0x3F]]);

    if nt_offset < dos_header.len() as i32
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("The e_lfanew offset {nt_offset} is negative or overlaps the DOS header."));
        let _ = error_handle::handle_std_error(&error, "Validating process PE image", print_errors);

        return Err(error);
    }

    let Some(nt_headers_address) = image_base_address.checked_add(nt_offset as usize) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The NT header address overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Validating process PE image", print_errors);

        return Err(error);
    };

    let mut signature = [0_u8; PE_SIGNATURE.len()];
    read_process_bytes(handle, nt_headers_address, &mut signature, "NtReadVirtualMemory(PE signature)", print_errors)?;

    if !contains_signature(&signature, &PE_SIGNATURE)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The e_lfanew address does not contain the PE signature.");
        let _ = error_handle::handle_std_error(&error, "Validating process PE image", print_errors);
        return Err(error);
    }

    Ok(nt_headers_address)
}


/// Verifies a borrowed process's image signatures and returns its owned x86/x64 COFF file header after basic field checks; print_errors controls reporting, and optional headers/sections remain unparsed.
pub fn query_process_image_file_header(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool) -> io::Result<IMAGE_FILE_HEADER>
{
    let nt_headers_address = validate_process_pe_image(handle, image_base_address, print_errors)?;
    read_image_file_header(handle, nt_headers_address, print_errors)
}


/// Returns a borrowed process image's common optional-header fields after checking its declared length, machine/magic pairing, sizes, alignment, and address bounds; print_errors controls failure reporting.
pub fn query_process_image_optional_header(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool) -> io::Result<ProcessOptionalHeader>
{
    let nt_headers_address = validate_process_pe_image(handle, image_base_address, print_errors)?;
    let file_header = read_image_file_header(handle, nt_headers_address, print_errors)?;
    read_image_optional_header(handle, image_base_address, nt_headers_address, &file_header, print_errors)
}


/// Reads the optional-header prefix using an already validated COFF header and NT signature address; returns checked common layout fields and optionally reports failures.
fn read_image_optional_header(handle: BorrowedHandle<'_>, image_base_address: usize, nt_headers_address: usize, file_header: &IMAGE_FILE_HEADER, print_errors: bool) -> io::Result<ProcessOptionalHeader>
{

    let Some(optional_header_address) = nt_headers_address.checked_add(PE_SIGNATURE.len() + size_of::<IMAGE_FILE_HEADER>()) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The optional header address overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    };

    let Some(declared_end_address) = optional_header_address.checked_add(file_header.SizeOfOptionalHeader as usize) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The declared optional header range overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    };

    let mut bytes = [0_u8; offset_of!(IMAGE_OPTIONAL_HEADER64, SizeOfHeaders) + size_of::<u32>()];
    read_process_bytes(handle, optional_header_address, &mut bytes, "NtReadVirtualMemory(optional header prefix)", print_errors)?;
    let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
    let expected_magic = if file_header.Machine == IMAGE_FILE_MACHINE_I386
    {
        IMAGE_NT_OPTIONAL_HDR32_MAGIC
    }
    else
    {
        IMAGE_NT_OPTIONAL_HDR64_MAGIC
    };

    if magic != expected_magic
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("Optional-header magic 0x{magic:04X} does not match machine 0x{:04X}; expected 0x{expected_magic:04X}.", file_header.Machine));
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    }

    let header = ProcessOptionalHeader
    {
        magic,
        size_of_image: u32::from_le_bytes([bytes[0x38], bytes[0x39], bytes[0x3A], bytes[0x3B]]),
        size_of_headers: u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]),
        section_alignment: u32::from_le_bytes([bytes[0x20], bytes[0x21], bytes[0x22], bytes[0x23]]),
    };

    if header.section_alignment == 0 || header.size_of_image == 0 || header.size_of_headers == 0 || header.size_of_headers > header.size_of_image
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("Invalid optional-header layout: image size={}, header size={}, section alignment={}.", header.size_of_image, header.size_of_headers, header.section_alignment));
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    }

    if !header.size_of_image.is_multiple_of(header.section_alignment)
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "SizeOfImage is not a multiple of SectionAlignment.");
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    }

    if declared_end_address - image_base_address > header.size_of_headers as usize
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The declared optional header extends beyond SizeOfHeaders.");
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    }

    if image_base_address.checked_add(header.size_of_image as usize).is_none()
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The declared image range overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process optional header", print_errors);

        return Err(error);
    }

    Ok(header)
}


/// Reads and validates the COFF header following a previously verified NT signature address; returns the native header and optionally reports failures.
/// SAFETY: The full header is read into an initialized, size-matched byte array before an unaligned local copy; IMAGE_FILE_HEADER contains only integer fields and Windows x64 uses the PE format's little-endian representation.
fn read_image_file_header(handle: BorrowedHandle<'_>, nt_headers_address: usize, print_errors: bool) -> io::Result<IMAGE_FILE_HEADER>
{

    let Some(file_header_address) = nt_headers_address.checked_add(PE_SIGNATURE.len()) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The COFF file header address overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process IMAGE_FILE_HEADER", print_errors);

        return Err(error);
    };

    let mut bytes = [0_u8; size_of::<IMAGE_FILE_HEADER>()];
    read_process_bytes(handle, file_header_address, &mut bytes, "NtReadVirtualMemory(IMAGE_FILE_HEADER)", print_errors)?;

    let header = unsafe
    {
        std::ptr::read_unaligned(bytes.as_ptr().cast::<IMAGE_FILE_HEADER>())
    };

    let minimum_optional_size = match header.Machine
    {
        IMAGE_FILE_MACHINE_I386 => offset_of!(IMAGE_OPTIONAL_HEADER32, DataDirectory),
        IMAGE_FILE_MACHINE_AMD64 => offset_of!(IMAGE_OPTIONAL_HEADER64, DataDirectory),
        _ =>
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, format!("Unsupported PE machine type 0x{:04X}; expected x86 or x64.", header.Machine));
            let _ = error_handle::handle_std_error(&error, "Querying process IMAGE_FILE_HEADER", print_errors);

            return Err(error);
        }
    };

    if header.NumberOfSections == 0 || header.NumberOfSections as usize > MAX_IMAGE_SECTIONS
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("The PE declares {} sections; expected 1 through {MAX_IMAGE_SECTIONS}.", header.NumberOfSections));
        let _ = error_handle::handle_std_error(&error, "Querying process IMAGE_FILE_HEADER", print_errors);

        return Err(error);
    }

    if header.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The COFF header does not mark the image as executable.");
        let _ = error_handle::handle_std_error(&error, "Querying process IMAGE_FILE_HEADER", print_errors);

        return Err(error);
    }

    if (header.SizeOfOptionalHeader as usize) < minimum_optional_size
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, format!("The declared optional header is {} bytes; this machine type requires at least {minimum_optional_size}.", header.SizeOfOptionalHeader));
        let _ = error_handle::handle_std_error(&error, "Querying process IMAGE_FILE_HEADER", print_errors);

        return Err(error);
    }

    Ok(header)
}


/// Reads one PEB ImageBaseAddress field at the target's pointer width, validating address arithmetic, byte count, and a nonzero result; optionally reports failures.
fn read_image_base_address(handle: BorrowedHandle<'_>, peb_base_address: usize, is_wow64: bool, print_errors: bool) -> io::Result<usize>
{
    let (offset, width) = if is_wow64
    {
        (PEB32_IMAGE_BASE_OFFSET, size_of::<u32>())
    }
    else
    {
        (PEB64_IMAGE_BASE_OFFSET, size_of::<u64>())
    };

    let Some(field_address) = peb_base_address.checked_add(offset) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The PEB image address field overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Reading PEB ImageBaseAddress", print_errors);
        return Err(error);
    };

    let mut bytes = [0_u8; 8];
    
    read_process_bytes(handle, field_address, &mut bytes[..width], "NtReadVirtualMemory(PEB ImageBaseAddress)", print_errors)?;

    let image_base_address = u64::from_le_bytes(bytes) as usize;

    if image_base_address == 0
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The PEB reports a null main image address.");
        let _ = error_handle::handle_std_error(&error, "Reading PEB ImageBaseAddress", print_errors);

        return Err(error);
    }

    Ok(image_base_address)
}


/// Reads exactly the supplied buffer length from a remote address, checking range arithmetic and native transfer counts; reports failures according to print_errors.
/// SAFETY: The borrowed process handle remains live, the mutable slice provides a writable buffer of the requested length, and remote addresses are passed to NtReadVirtualMemory without local dereferencing.
fn read_process_bytes(handle: BorrowedHandle<'_>, address: usize, bytes: &mut [u8], context: &str, print_errors: bool) -> io::Result<()>
{
    if address.checked_add(bytes.len()).is_none()
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The remote memory read overflows the address range.");
        let _ = error_handle::handle_std_error(&error, context, print_errors);
        return Err(error);
    }

    let mut bytes_read = 0;
    let apis = process_apis(print_errors)?;

    let status = unsafe
    {
        (apis.nt_read_virtual_memory)(handle.as_raw_handle(), address as *const c_void, bytes.as_mut_ptr().cast(), bytes.len(), &mut bytes_read)
    };

    if status < 0
    {
        return Err(error_handle::handle_ntstatus_error(status, context, print_errors));
    }

    if bytes_read != bytes.len()
    {
        let error = io::Error::new(io::ErrorKind::UnexpectedEof, format!("The remote memory read returned {bytes_read} bytes; expected {}.", bytes.len()));
        let _ = error_handle::handle_std_error(&error, context, print_errors);
        return Err(error);
    }

    Ok(())
}
