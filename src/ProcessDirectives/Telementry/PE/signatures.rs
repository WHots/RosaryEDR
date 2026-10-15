/// DOS header marker MZ (0x5A4D); check at the image base when validating a PE.
pub const MZ_SIGNATURE: [u8; 2] = [0x4D, 0x5A];

/// NT header marker PE\0\0 (0x00004550); check at the DOS header's e_lfanew offset.
pub const PE_SIGNATURE: [u8; 4] = [0x50, 0x45, 0x00, 0x00];

/// Single-byte x64 NOP instruction; useful for recognizing instruction padding.
pub const X64_NOP: [u8; 1] = [0x90];

/// Single-byte x64 near RET instruction; useful for locating possible function returns.
pub const X64_RET: [u8; 1] = [0xC3];

/// Single-byte x64 INT3 instruction; useful for recognizing breakpoint bytes or padding.
pub const X64_INT3: [u8; 1] = [0xCC];


/// Searches successfully read bytes for an exact contiguous signature; returns false for empty signatures, insufficient data, or no match, without allocation or memory API calls.
pub fn contains_signature(read_bytes: &[u8], signature: &[u8]) -> bool
{
    if signature.is_empty() || signature.len() > read_bytes.len()
    {
        return false;
    }

    read_bytes.windows(signature.len()).any(|bytes| bytes == signature)
}


#[cfg(test)]
mod tests
{
    use super::*;


    /// Confirms exact matches at both buffer boundaries and overlapping candidate positions are found.
    #[test]
    fn finds_boundary_and_overlapping_matches()
    {
        assert!(contains_signature(b"MZ", &MZ_SIGNATURE));
        assert!(contains_signature(b"MZdata", &MZ_SIGNATURE));
        assert!(contains_signature(b"dataMZ", &MZ_SIGNATURE));
        assert!(contains_signature(b"dataPE\0\0tail", &PE_SIGNATURE));
        assert!(contains_signature(&[0xAB, 0xAB, 0xAB, 0xCD], &[0xAB, 0xAB, 0xCD]));
    }


    /// Confirms empty input/patterns, truncated signatures, and changed literal zero bytes do not match.
    #[test]
    fn rejects_empty_short_and_incomplete_signatures()
    {
        assert!(!contains_signature(&[], &MZ_SIGNATURE));
        assert!(!contains_signature(b"MZ", &[]));
        assert!(!contains_signature(&[], &[]));
        assert!(!contains_signature(b"M", &MZ_SIGNATURE));
        assert!(!contains_signature(b"PE\0", &PE_SIGNATURE));
        assert!(!contains_signature(b"PE\0X", &PE_SIGNATURE));
        assert!(!contains_signature(b"unrelated", &PE_SIGNATURE));
    }


}
