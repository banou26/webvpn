use std::net::{IpAddr, SocketAddr};

use crate::error::DecodeError;

pub(crate) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < length {
            return Err(DecodeError::Truncated);
        }
        let (head, tail) = self.0.split_at(length);
        self.0 = tail;
        Ok(head)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().expect("take returned N bytes"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        Ok(self.u8()? != 0)
    }

    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    pub fn rest(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }

    pub fn address(&mut self) -> Result<SocketAddr, DecodeError> {
        self.optional_address()?.ok_or(DecodeError::Invalid("an address is required here"))
    }

    pub fn optional_address(&mut self) -> Result<Option<SocketAddr>, DecodeError> {
        let ip = match self.u8()? {
            0 => IpAddr::from(self.array::<4>()?),
            1 => IpAddr::from(self.array::<16>()?),
            2 => return Ok(None),
            _ => return Err(DecodeError::Invalid("unknown address family")),
        };
        Ok(Some(SocketAddr::new(ip, self.u16()?)))
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_address(out: &mut Vec<u8>, address: Option<SocketAddr>) {
    match address {
        Some(SocketAddr::V4(v4)) => {
            out.push(0);
            out.extend_from_slice(&v4.ip().octets());
            put_u16(out, v4.port());
        }
        Some(SocketAddr::V6(v6)) => {
            out.push(1);
            out.extend_from_slice(&v6.ip().octets());
            put_u16(out, v6.port());
        }
        None => out.push(2),
    }
}
