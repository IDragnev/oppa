use std::{
    fmt,
};
use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::map,
    bytes::complete::take,
    number::complete::be_u16,
    sequence::tuple,
    error::context,
};
use crate::parse;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Addr([u8; 6]);

impl Addr {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context(
            "MAC Address",
            map(take(6_usize), Self::new_unchecked),
        )(i)
    }

    fn new_unchecked(bytes: &[u8]) -> Self {
        let mut addr = Self([0; 6]);
        addr.0.copy_from_slice(&bytes[..6]);
        addr
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> fmt::Result {
        let [a, b, c, d, e, f] = self.0;
        write!(formatter,
               "{:02X}-{:02X}-{:02X}-{:02X}-{:02X}-{:02X}",
               a, b, c, d, e, f
        )
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum EtherType {
    IPv4 = 0x0800,
}

impl EtherType {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let original_i = i;
        let (i, x) = context("EtherType", be_u16)(i)?;

        match EtherType::try_from(x) {
            Ok(typ) => Ok((i, typ)),
            Err(_) => {
                use nom::Offset;
                let msg = format!("unknown EtherType 0x{:04X}", x);
                let err_slice = &original_i[..original_i.offset(i)];

                Err(nom::Err::Error(parse::Error::custom(err_slice, msg)))
            }
        }
    }
}

#[derive(Debug)]
pub struct Frame {
    pub dst: Addr,
    pub src: Addr,
    pub ether_type: EtherType,
}

impl Frame {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context(
            "Ethernet frame",
            map(
                tuple((Addr::parse, Addr::parse, EtherType::parse)),
                |(dst, src, ether_type)| Self {
                    dst,
                    src,
                    ether_type,
            }),
        )(i)
    }
}