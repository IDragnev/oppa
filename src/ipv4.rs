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
    bits::bits,
};
use crate::parse::BitParsable;

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
    #[debug(skip)]
    pub version: ux::u4,
    #[debug(format = "{}")]
    pub ihl: ux::u4,
    #[debug(format = "{:x}")]
    pub dscp: ux::u6,
    #[debug(format = "{:b}")]
    pub ecn: ux::u2,
    pub length: u16,

    #[debug(format = "{:04x}")]
    pub identification: u16,
    #[debug(format = "{:b}")]
    pub flags: ux::u3,
    #[debug(format = "{}")]
    pub fragment_offset: ux::u13,

    #[debug(format = "{}")]
    pub ttl: u8,
    #[debug(skip)]
    pub protocol: Option<Protocol>,
    #[debug(format = "{:04x}")]
    pub checksum: u16,

    pub src: Addr,
    pub dst: Addr,

    pub payload: Payload,
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
        use ux::{u2, u3, u4, u6, u13};
        use nom::Offset;

        let original_i = i;
        let (i, (version, ihl)) = bits(tuple((u4::parse, u4::parse)))(i)?;

        if u8::from(version) != 4 {
            let msg = format!("Invalid IPv4 version {} (expected 4)", version);
            let err_slice = &original_i[..original_i.offset(i)];
            return Err(nom::Err::Error(parse::Error::custom(err_slice, msg)));
        }

        let (i, (dscp, ecn)) = bits(tuple((u6::parse, u2::parse)))(i)?;
        let (i, length) = be_u16(i)?;

        let (i, identification) = be_u16(i)?;
        let (i, (flags, fragment_offset)) = bits(tuple((u3::parse, u13::parse)))(i)?;

        let (i, ttl) = be_u8(i)?;
        let (i, protocol) = Protocol::parse(i)?;
        let (i, checksum) = be_u16(i)?;
        let (i, (src, dst)) = tuple((Addr::parse, Addr::parse))(i)?;

        // let (i, payload) = match protocol {
        //     Some(Protocol::ICMP) => map(icmp::Packet::parse, Payload::ICMP)(i)?,
        //     _ => (i, Payload::Unknown),
        // };

        let res = Self {
            version,
            ihl,
            dscp,
            ecn,
            length,
            identification,
            flags,
            fragment_offset,
            ttl,
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