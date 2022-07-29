use std::{
    fmt,
    io,
};
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
    combinator::map,
};
use crate::{
    parse::{
        self, 
        BitParsable,
    },
    icmp,
};
use cookie_factory as cf;

#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct Addr(pub [u8; 4]);

#[derive(Debug, TryFromPrimitive, Copy, Clone)]
#[repr(u8)]
pub enum Protocol {
    ICMP = 0x01,
    TCP = 0x06,
    UDP = 0x11,
}

#[derive(Debug, Clone)]
pub enum Payload {
    ICMP(icmp::Packet),
    Unknown,
}

#[derive(CustomDebug, Clone)]
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

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::bytes::be_u8;
        be_u8(*self as u8)
    }
}

impl Addr {
    pub fn zero() -> Self {
        return Self([0, 0, 0, 0])
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, slice) = context("IPv4 address", take(4_usize))(i)?;
        let mut res = Self([0, 0, 0, 0]);
        res.0.copy_from_slice(slice);
        Ok((i, res))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::combinator::slice;
        slice(&self.0)
    }
}

impl Payload {
    pub fn protocol(&self) -> Protocol {
        match self {
            Self::ICMP(_) => Protocol::ICMP,
            _ => unimplemented!(),
        }
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        move |out| match self {
            Self::ICMP(ref icmp) => icmp.serialize()(out),
            _ => unimplemented!(),
        }
    }
}

impl Packet {
    pub fn new(src: Addr, dst: Addr, p: Payload) -> Self {
        Self {
            protocol: Some(p.protocol()),
            payload: p,
            src,
            dst,
            ..Default::default()
        }
    }

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

        let (i, payload) = match protocol {
            Some(Protocol::ICMP) => map(icmp::Packet::parse, Payload::ICMP)(i)?,
            _ => (i, Payload::Unknown),
        };

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
            payload,
        };

        Ok((i, res))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::le_u16, bytes::be_u16, combinator::slice};

        move |out| {
            let mut buf = cf::gen_simple(self.serialize_no_checksum(), Vec::new())?;

            let length = buf.len() as u16;
            cf::gen_simple(be_u16(length), &mut buf[2..])?;

            // note: this will break if we ever allow IP options
            let header_slice = &buf[..5 * 4];
            let checksum = crate::ipv4::checksum(header_slice);
            cf::gen_simple(le_u16(checksum), &mut buf[10..])?;

            slice(buf)(out)
        }
    }

    pub fn serialize_no_checksum<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use crate::serialize::{bits, BitSerialize};
        use cf::{
            bytes::{be_u16, be_u8},
            sequence::tuple,
        };
        use ux::*;

        tuple((
            bits(move |bo| {
                let version = u4::new(4);
                let ihl = u4::new(5);
                let dscp = u6::new(0);
                let ecn = u2::new(0);

                version.write(bo);
                ihl.write(bo);
                dscp.write(bo);
                ecn.write(bo);
            }),
            be_u16(0), // length, to fill later
            be_u16(self.identification),
            bits(move |bo| {
                let flags = u3::new(0);
                let fragment_offset = u13::new(0);

                flags.write(bo);
                fragment_offset.write(bo);
            }),
            be_u8(self.ttl),
            // we need to do this to avoid capturing a temporary
            move |out| self.payload.protocol().serialize()(out),
            be_u16(0), // checksum, to fill later
            self.src.serialize(),
            self.dst.serialize(),
            self.payload.serialize(),
        ))
    }
}

impl Default for Packet {
    fn default() -> Self {
        use ux::*;

        Self {
            length: 0,
            identification: rand::random(),
            version: u4::new(4),
            ihl: u4::new(5),
            dscp: u6::new(0),
            ecn: u2::new(0),
            flags: u3::new(0),
            fragment_offset: u13::new(0),
            ttl: 128,
            protocol: None,
            checksum: 0,
            src: Addr::zero(),
            dst: Addr::zero(),
            payload: Payload::Unknown,
        }
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{}.{}.{}.{}", a, b, c, d)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseAddrError {
    #[error("too many octets")]
    TooManyOctets,
    #[error("insufficient octets")]
    InsufficientOctets,
    #[error("invalid octet {0:?}")]
    InvalidOctet(#[from] std::num::ParseIntError),
}

impl std::str::FromStr for Addr {
    type Err = ParseAddrError;

    fn from_str(s: &str) -> Result<Self, ParseAddrError> {
        let mut tokens = s.split(".");

        let mut res = Self([0, 0, 0, 0]);
        for part in res.0.iter_mut() {
            let oct = tokens.next()
                            .ok_or(ParseAddrError::InsufficientOctets)?;

            *part = u8::from_str_radix(oct, 10)
                    .map_err(|e| ParseAddrError::InvalidOctet(e))?
        }

        if let Some(_) = tokens.next() {
            return Err(ParseAddrError::TooManyOctets);
        }

        Ok(res)
    }
}

pub fn checksum(slice: &[u8]) -> u16 {
    let (head, slice, tail) = unsafe { slice.align_to::<u16>() };
    if head.is_empty() == false {
        panic!("checksum() input should be 16-bit aligned");
    }

    fn add(a: u16, b: u16) -> u16 {
        let s: u32 = (a as u32) + (b as u32);
        if s & 0x1_00_00 > 0 {
            // overflow, add carry bit
            (s + 1) as u16
        } else {
            s as u16
        }
    }

    let odd_byte = tail.iter().next().map(|&x| x as u16).unwrap_or(0);
    let sum = slice.iter().fold(odd_byte, |x, y| add(x, *y));
    !sum
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_addr_with_insufficient_octets_fails() {
        assert!(matches!(Addr::from_str("8"), Err(ParseAddrError::InsufficientOctets)));
        assert!(matches!(Addr::from_str("8.8"), Err(ParseAddrError::InsufficientOctets)));
        assert!(matches!(Addr::from_str("8.8.8"), Err(ParseAddrError::InsufficientOctets)));
    }

    #[test]
    fn parse_addr_with_too_many_octets_fails() {
        assert!(matches!(Addr::from_str("8.8.8.8.8"), Err(ParseAddrError::TooManyOctets)));
    }

    #[test]
    fn parse_addr_with_invalid_octet_fails() {
        assert!(matches!(Addr::from_str(""), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::from_str("8."), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::from_str("8.x.8.8"), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::from_str("8.256.8.8"), Err(ParseAddrError::InvalidOctet(_))));
    }

    #[test]
    fn parse_addr_with_correct_addres_is_ok() {
        assert!(matches!(Addr::from_str("8.8.8.8"), Ok(_)));
    }
}