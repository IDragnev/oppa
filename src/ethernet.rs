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
use crate::{
    parse,
    ipv4,
};
use custom_debug_derive::*;

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
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        let (i, x) = context("EtherType", be_u16)(i)?;

        match EtherType::try_from(x) {
            Ok(typ) => Ok((i, Some(typ))),
            Err(_) => Ok((i, None)),
        }
    }
}

#[derive(Debug)]
pub enum Payload {
    IPv4(ipv4::Packet),
    Unknown,
}

#[derive(CustomDebug)]
pub struct Frame {
    pub dst: Addr,
    pub src: Addr,
    #[debug(skip)]
    pub ether_type: Option<EtherType>,
    pub payload: Payload,
}

impl Frame {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        context("Ethernet frame", |i| {
            let (i, (dst, src)) = tuple((Addr::parse, Addr::parse))(i)?;
            let (i, ether_type) = EtherType::parse(i)?;

            let (i, payload) = match ether_type {
                Some(EtherType::IPv4) => map(ipv4::Packet::parse, Payload::IPv4)(i)?,
                None => (i, Payload::Unknown),
            };

            let res = Self {
                dst,
                src,
                ether_type,
                payload,
            };

            Ok((i, res))
        })(i)
    }
}