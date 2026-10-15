use super::{read_image_file_header, read_image_optional_header, read_process_bytes, validate_process_pe_image, ProcessOptionalHeader, MAX_IMAGE_SECTIONS};
use crate::error_handle;
use std::io;
use std::mem::size_of;
use std::os::windows::io::BorrowedHandle;
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER};

/// Owned PE section metadata with a numeric remote address and declared byte span; header characteristics do not describe current memory-page protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessSection
{
    pub name: [u8; 8],
    pub address: usize,
    pub size: u32,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub raw_data_offset: u32,
    pub characteristics: u32,
}


/// Private image base and header snapshot, constructed only after the shared PE/COFF/optional-header checks succeed.
struct ValidatedImage
{
    image_base_address: usize,
    nt_headers_address: usize,
    file_header: IMAGE_FILE_HEADER,
    optional_header: ProcessOptionalHeader,
}


/// Collects owned section records after the private image-header validator succeeds, checking the table and declared ranges; addresses are for later native memory reads, and print_errors controls failure reporting.
/// SAFETY: Each native section header is copied unaligned from a fully read, size-matched local slice; its fields and VirtualSize union member are integer data, and remote addresses are never dereferenced locally.
pub fn query_process_sections(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool) -> io::Result<Vec<ProcessSection>>
{
    let ValidatedImage { image_base_address, nt_headers_address, file_header, optional_header } = validate_image_headers(handle, image_base_address, print_errors)?;

    let Some(table_address) = nt_headers_address.checked_add(4 + size_of::<IMAGE_FILE_HEADER>() + file_header.SizeOfOptionalHeader as usize) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The section table address overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

        return Err(error);
    };

    let section_count = file_header.NumberOfSections as usize;
    
    let Some(table_length) = section_count.checked_mul(size_of::<IMAGE_SECTION_HEADER>()) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The section table length overflows the size range.");
        let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

        return Err(error);
    };

    let Some(table_end_address) = table_address.checked_add(table_length) else
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The section table range overflows the address range.");
        let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

        return Err(error);
    };

    if table_end_address - image_base_address > optional_header.size_of_headers as usize
    {
        let error = io::Error::new(io::ErrorKind::InvalidData, "The section table extends beyond SizeOfHeaders.");
        let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

        return Err(error);
    }

    let mut table = [0_u8; MAX_IMAGE_SECTIONS * size_of::<IMAGE_SECTION_HEADER>()];

    read_process_bytes(handle, table_address, &mut table[..table_length], "NtReadVirtualMemory(section table)", print_errors)?;
    
    let mut sections = Vec::new();

    if let Err(allocation_error) = sections.try_reserve_exact(section_count)
    {
        let error = io::Error::new(io::ErrorKind::OutOfMemory, allocation_error);
        let _ = error_handle::handle_std_error(&error, "Allocating process section records", print_errors);

        return Err(error);
    }

    for (index, bytes) in table[..table_length].chunks_exact(size_of::<IMAGE_SECTION_HEADER>()).enumerate()
    {
        let header = unsafe
        {
            std::ptr::read_unaligned(bytes.as_ptr().cast::<IMAGE_SECTION_HEADER>())
        };

        let virtual_size = unsafe
        {
            header.Misc.VirtualSize
        };

        let size = virtual_size.max(header.SizeOfRawData);

        if !header.VirtualAddress.is_multiple_of(optional_header.section_alignment)
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, format!("Section {} has an RVA that does not match SectionAlignment.", index + 1));
            let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

            return Err(error);
        }

        let Some(end_rva) = header.VirtualAddress.checked_add(size) else
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, format!("Section {} has an overflowing RVA/size range.", index + 1));
            let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

            return Err(error);
        };

        if end_rva > optional_header.size_of_image
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, format!("Section {} extends beyond SizeOfImage.", index + 1));
            let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

            return Err(error);
        }

        let Some(address) = image_base_address.checked_add(header.VirtualAddress as usize) else
        {
            let error = io::Error::new(io::ErrorKind::InvalidData, format!("Section {} has an overflowing remote address.", index + 1));
            let _ = error_handle::handle_std_error(&error, "Querying process sections", print_errors);

            return Err(error);
        };

        sections.push(ProcessSection
        {
            name: header.Name,
            address,
            size,
            virtual_address: header.VirtualAddress,
            virtual_size,
            raw_data_size: header.SizeOfRawData,
            raw_data_offset: header.PointerToRawData,
            characteristics: header.Characteristics,
        });
    }

    Ok(sections)
}


/// Validates a borrowed process image through the shared helpers; returns its checked base and header snapshot only on success, with print_errors forwarded for failure reporting.
fn validate_image_headers(handle: BorrowedHandle<'_>, image_base_address: usize, print_errors: bool) -> io::Result<ValidatedImage>
{
    let nt_headers_address = validate_process_pe_image(handle, image_base_address, print_errors)?;
    let file_header = read_image_file_header(handle, nt_headers_address, print_errors)?;
    let optional_header = read_image_optional_header(handle, image_base_address, nt_headers_address, &file_header, print_errors)?;

    Ok(ValidatedImage
    {
        image_base_address,
        nt_headers_address,
        file_header,
        optional_header,
    })
}
