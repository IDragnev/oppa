use std::{
    fmt,
};
use crate::parse;
use derive_try_from_primitive::*;
use custom_debug_derive::*;
use nom::{
    bytes::complete::take,
    error::context,
    number::complete::{
        be_u16,
        be_u8
    },
    sequence::tuple,
};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Addr(pub [u8; 4]);

#[derive(Debug, TryFromPrimitive)]
#[repr(u8)]
pub enum Protocol {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
}

#[derive(Debug)]
pub enum Payload {
    Unknown,
}

#[derive(CustomDebug)]
pub struct Packet {
    src: Addr,
    dst: Addr,
    #[debug(skip)]
    checksum: u16,
    #[debug(skip)]
    pub protocol: Option<Protocol>,
    payload: Payload,
}

impl Protocol {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        let (i, x) = context("IPv4 Protocol", be_u8)(i)?;

        match Self::try_from(x) {
            Ok(typ) => Ok((i, Some(typ))),
            Err(_) => Ok((i, None)),
        }
    }
}

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, slice) = context("IPv4 address", take(4_usize))(i)?;
        let mut res = Self([0, 0, 0, 0]);
        res.0.copy_from_slice(slice);
        Ok((i, res))
    }
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        // skip over those first 9 bytes for now
        let (i, _) = take(9_usize)(i)?;
        let (i, protocol) = Protocol::parse(i)?;
        let (i, checksum) = be_u16(i)?;
        let (i, (src, dst)) = tuple((Addr::parse, Addr::parse))(i)?;
        let res = Self {
            protocol,
            checksum,
            src,
            dst,
            payload: Payload::Unknown,
        };

        Ok((i, res))
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{}.{}.{}.{}", a, b, c, d)
    }
}