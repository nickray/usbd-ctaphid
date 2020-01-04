const CONSTRUCTED: u8 = 1 << 5;
// const CONTEXT_SPECIFIC: u8 = 2 << 6;

/// ASN.1 Tags
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum Tag {
    // Eoc = 0x00,
    // Boolean = 0x01,
    Integer = 0x02,
    // BitString = 0x03,
    // OctetString = 0x04,
    // Null = 0x05,
    // Oid = 0x06,
    Sequence = CONSTRUCTED | 0x10, // 0x30 or decimal 48
    // UtcTime = 0x17,
    // GeneralizedTime = 0x18,
    // ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED | 0,
    // ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    // ContextSpecificConstructed2 = CONTEXT_SPECIFIC | CONSTRUCTED | 2,
    // ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,
}

impl From<Tag> for usize {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

// the only error is buffer overflow
type Result = core::result::Result<(), ()>;

/// DER writer
#[derive(Debug)]
pub struct Der<'a> {
    buffer: &'a mut [u8],
    offset: usize,
}

impl<'a> core::ops::Deref for Der<'a> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.buffer[..self.offset]
    }
}

impl<'a> core::ops::DerefMut for Der<'a> {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.buffer[..self.offset]
    }
}

impl<'a> Der<'a> {
    /// Create a new `Der` structure that writes values to the given buffer
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Der { buffer, offset: 0 }
    }

    // equivalent of method in std::io::Write
    fn write_all(&mut self, data: &[u8]) -> Result {
        if self.offset + data.len() > self.buffer.len() {
            Err(())
        } else {
            self.buffer[self.offset..][..data.len()].copy_from_slice(data);
            self.offset += data.len();
            Ok(())
        }
    }

    // https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-encoded-length-and-value-bytes
    fn write_length_field(&mut self, length: usize) -> Result {
        if length < 0x80 {
            // values under 128: write length directly as u8
            self.write_all(&[length as u8])
        } else {
            // values at least 128:
            // - write number of bytes needed as u8, setting bit 7
            // - write l as big-endian bytes representation, with minimal length

            let mut repr = &length.to_be_bytes()[..];
            while repr[0] == 0 {
                repr = &repr[1..];
            }
            self.write_all(&[0x80 | repr.len() as u8])?;
            self.write_all(repr)
        }
    }

    // /// Write a `NULL` tag.
    // pub fn null(&mut self) -> Result {
    //     self.write_all(&[Tag::Null as u8, 0])?;
    //     Ok(())
    // }

    /// Write an arbitrary tag-length-value
    pub fn raw_tlv(&mut self, tag: Tag, value: &[u8]) -> Result {
        self.write_all(&[tag as u8])?;
        self.write_length_field(value.len())?;
        self.write_all(value)?;
        Ok(())
    }

    /// Write the given input as integer.
    ///
    /// Assumes `input` is the big-endian representation of a non-negative `Integer`
    ///
    /// Not sure about good references, maybe:
    /// https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-integer
    ///
    /// From: https://docs.rs/ecdsa/0.3.0/src/ecdsa/convert.rs.html#205-219
    /// Compute ASN.1 DER encoded length for the provided scalar.
    /// The ASN.1 encoding is signed, so its leading bit must have value 0;
    /// it must also be of minimal length (so leading bytes of value 0 must be
    /// removed, except if that would contradict the rule about the sign bit).
    pub fn non_negative_integer(&mut self, mut integer: &[u8]) -> Result {
        self.write_all(&[Tag::Integer as u8])?;

        // strip leading zero bytes
        while !integer.is_empty() && integer[0] == 0 {
            integer = &integer[1..];
        }

        if integer.is_empty() || integer[0] >= 0x80 {
            self.write_length_field(integer.len() + 1)?;
            self.write_all(&[0x00])?;
        } else {
            self.write_length_field(integer.len())?;
        }

        self.write_all(integer)
    }

    /// Write a nested structure by passing in a handling function that writes
    /// the serialized intermediate structure.
    fn nested<F>(&mut self, tag: Tag, f: F) -> Result
    where
        F: FnOnce(&mut Der<'a>) -> Result,
    {
        let before = self.offset;

        // serialize the nested structure
        f(self)?;
        let written = self.offset - before;

        // generate Tag-Length prefix
        // 1 for tag, 1 for length prefix, 4 or 8 for usize itself
        let mut tmp = [0u8; 2 + core::mem::size_of::<usize>()];
        let mut prefix = Der::new(&mut tmp);

        // generate prefix consisting of "tag" and length of nested structure
        prefix.write_all(&[tag as u8])?;
        prefix.write_length_field(written)?;
        let shift = prefix.offset;

        // check if prefix and nested structure both fit
        if self.offset + shift > self.buffer.len() {
            return Err(());
        }

        // shift nested structure back
        self.buffer.copy_within(before..self.offset, before + shift);

        // add tag + length prefix
        self.buffer[before..][..shift].copy_from_slice(&tmp[..shift]);
        self.offset += shift;

        Ok(())
    }

    /// Write a `SEQUENCE` by passing in a handling function that writes to an intermediate `Vec`
    /// before writing the whole sequence to `self`.
    pub fn sequence<F>(&mut self, f: F) -> Result
    where
        F: FnOnce(&mut Der<'a>) -> Result,
    {
        self.nested(Tag::Sequence, f)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn max_prefix() {
        let mut u32_buf = [0u8; core::mem::size_of::<u32>() + 2];
        let mut prefix = Der::new(&mut u32_buf);
        prefix.write_all(&[0u8]).unwrap();
        assert!(prefix.write_length_field(u32::max_value() as usize).is_ok());
        assert_eq!([0u8, 132, 255, 255, 255, 255], prefix.as_ref());

        let mut u64_buf = [0u8; core::mem::size_of::<u64>() + 2];
        let mut prefix = Der::new(&mut u64_buf);
        prefix.write_all(&[0u8]).unwrap();
        assert!(prefix.write_length_field(u64::max_value() as usize).is_ok());
        assert_eq!([0, 136, 255, 255, 255, 255, 255, 255, 255, 255], prefix.as_ref());
    }

    #[test]
    fn write_asn1_der_ecdsa_signature() {
        let r = [
            167u8, 156, 58, 251, 253, 197, 176, 208, 165, 146, 155, 16, 217, 152, 192, 243, 206,
            76, 214, 207, 207, 180, 237, 8, 156, 160, 64, 32, 147, 82, 213, 158,
        ];
        let s = [
            184, 156, 136, 100, 87, 142, 84, 61, 235, 27, 193, 223, 254, 97, 11, 111, 80, 37, 46,
            150, 121, 96, 165, 96, 65, 242, 211, 180, 175, 91, 158, 88,
        ];
        let mut buf = [0u8; 1024];
        let mut der = Der::new(&mut buf);
        der.sequence(|der| {
            {
                der.non_negative_integer(&r)?;
                der.non_negative_integer(&s)
            }
        })
        .unwrap();

        #[rustfmt::skip]
        let expected = [
            48u8, 70,
            2, 33,
                0, 167, 156, 58, 251, 253, 197, 176, 208, 165, 146, 155, 16, 217, 152,
                192, 243, 206, 76, 214, 207, 207, 180, 237, 8, 156, 160, 64, 32, 147, 82, 213, 158,
            2, 33,
                0, 184, 156, 136, 100, 87, 142, 84, 61, 235, 27, 193, 223, 254, 97, 11, 111, 80,
                37, 46, 150, 121, 96, 165, 96, 65, 242, 211, 180, 175, 91, 158, 88,
        ];
        assert_eq!(der.len(), expected.len());
        use crate::bytes::{consts, Bytes};
        assert_eq!(
            Bytes::<consts::U72>::try_from_slice(&der).unwrap(),
            Bytes::<consts::U72>::try_from_slice(&expected).unwrap(),
        );
        // assert_eq!(&got[..32], &expected[..32]);
        // assert_eq!(&got[32..64], &expected[32..64]);
        // assert_eq!(&got[64..], &expected[64..]);
    }
}

// let mut der = Der::new(&mut buf);
// der.sequence(|der| {
//     der.positive_integer(n)?;
//     der.positive_integer(e)
// })
// .unwrap();

// /// Write an `OBJECT IDENTIFIER`.
// pub fn oid(&mut self, input: &[u8]) -> Result<()> {
//     self.writer.write_all(&[Tag::Oid as u8])?;
//     self.write_length_field(input.len())?;
//     self.writer.write_all(&input)?;
//     Ok(())
// }

// /// Write raw bytes to `self`. This does not calculate length or apply. This should only be used
// /// when you know you are dealing with bytes that are already DER encoded.
// pub fn raw(&mut self, input: &[u8]) -> Result<()> {
//     Ok(self.writer.write_all(input)?)
// }

// /// Write a `BIT STRING`.
// pub fn bit_string(&mut self, unused_bits: u8, bit_string: &[u8]) -> Result<()> {
//     self.writer.write_all(&[Tag::BitString as u8])?;
//     self.write_length_field(bit_string.len() + 1)?;
//     self.writer.write_all(&[unused_bits])?;
//     self.writer.write_all(&bit_string)?;
//     Ok(())
// }

// /// Write an `OCTET STRING`.
// pub fn octet_string(&mut self, octet_string: &[u8]) -> Result<()> {
//     self.writer.write_all(&[Tag::OctetString as u8])?;
//     self.write_length_field(octet_string.len())?;
//     self.writer.write_all(&octet_string)?;
//     Ok(())
// }
// }

// #[cfg(test)]
// mod test {
//     use super::*;
//     use untrusted::Input;
//     use Error;

//     static RSA_2048_PKCS1: &'static [u8] = include_bytes!("../tests/rsa-2048.pkcs1.der");

//     #[test]
//     fn write_pkcs1() {
//         let input = Input::from(RSA_2048_PKCS1);
//         let (n, e) = input
//             .read_all(Error::Read, |input| {
//                 der::nested(input, Tag::Sequence, |input| {
//                     let n = der::positive_integer(input)?;
//                     let e = der::positive_integer(input)?;
//                     Ok((n.as_slice_less_safe(), e.as_slice_less_safe()))
//                 })
//             })
//             .unwrap();

//         let mut buf = Vec::new();
//         {
//             let mut der = Der::new(&mut buf);
//             der.sequence(|der| {
//                 der.positive_integer(n)?;
//                 der.positive_integer(e)
//             })
//             .unwrap();
//         }

//         assert_eq!(buf.as_slice(), RSA_2048_PKCS1);
//     }

//     #[test]
//     fn write_octet_string() {
//         let mut buf = Vec::new();
//         {
//             let mut der = Der::new(&mut buf);
//             der.octet_string(&[]).unwrap();
//         }

//         assert_eq!(&buf, &[0x04, 0x00]);

//         let mut buf = Vec::new();
//         {
//             let mut der = Der::new(&mut buf);
//             der.octet_string(&[0x0a, 0x0b, 0x0c]).unwrap();
//         }

//         assert_eq!(&buf, &[0x04, 0x03, 0x0a, 0x0b, 0x0c]);
//     }
// }
