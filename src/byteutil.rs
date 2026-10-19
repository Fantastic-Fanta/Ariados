//! Small endian-aware reader over a byte slice.
//!
//! Binary headers are full of fixed-width integers at known offsets. Doing that
//! by hand with `u32::from_le_bytes(data[o..o+4].try_into()?)` everywhere is
//! noisy and easy to get wrong, so this wraps it with bounds checks that return
//! an error instead of panicking on a truncated or hostile file.

use crate::error::AnalyzeError;

pub type Result<T> = std::result::Result<T, AnalyzeError>;

/// A cursor into a byte buffer that reads integers in a fixed endianness.
#[derive(Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pub pos: usize,
    little: bool,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], little: bool) -> Self {
        Reader { data, pos: 0, little }
    }

    pub fn at(data: &'a [u8], pos: usize, little: bool) -> Self {
        Reader { data, pos, little }
    }

    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(AnalyzeError::Truncated { want: n, at: self.pos })?;
        let slice = self
            .data
            .get(self.pos..end)
            .ok_or(AnalyzeError::Truncated { want: n, at: self.pos })?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        let a = [b[0], b[1]];
        Ok(if self.little { u16::from_le_bytes(a) } else { u16::from_be_bytes(a) })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        let a = [b[0], b[1], b[2], b[3]];
        Ok(if self.little { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }

    pub fn i32(&mut self) -> Result<i32> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(if self.little { u64::from_le_bytes(a) } else { u64::from_be_bytes(a) })
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.take(n)?;
        Ok(())
    }

    /// Reads a fixed-size field and returns it as a trimmed UTF-8 string.
    /// Used for the 16-byte section and segment names in Mach-O, which are
    /// NUL-padded and may not fill the field.
    pub fn fixed_str(&mut self, n: usize) -> Result<String> {
        let raw = self.take(n)?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        Ok(String::from_utf8_lossy(&raw[..end]).into_owned())
    }

    /// Reads an unsigned LEB128 value (variable-length), used by Mach-O's
    /// `LC_FUNCTION_STARTS` table, which stores function addresses as deltas.
    pub fn uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 64 {
                result |= u64::from(byte & 0x7f) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift > 70 {
                return Err(AnalyzeError::Malformed("overlong LEB128".into()));
            }
        }
        Ok(result)
    }
}

/// Reads a little-endian u32 at an absolute offset, with bounds checking.
pub fn u32_le(data: &[u8], off: usize) -> Result<u32> {
    Reader::at(data, off, true).u32()
}
