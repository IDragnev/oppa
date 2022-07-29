use crate::{
    parse,
    blob::Blob,
    ipv4,
};
use custom_debug_derive::*;
use nom::{
    number::complete::{
        be_u8,
        be_u16,
        be_u32,
    },
    sequence::tuple,
    combinator::map,
};
use cookie_factory as cf;
use std::{
    io,
};

#[derive(Debug, Clone)]
pub enum Type {
    EchoReply,
    DestinationUnreachable(DestinationUnreachable),
    EchoRequest,
    TimeExceeded(TimeExceeded),
    Other(u8, u8),
}

#[derive(Debug, Clone)]
pub enum DestinationUnreachable {
    HostUnreachable,
    Other(u8),
}

#[derive(Debug, Clone)]
pub enum TimeExceeded {
    TTLExpired,
    Other(u8),
}

#[derive(CustomDebug, Clone)]
pub struct Echo {
    #[debug(format = "{:04x}")]
    pub identifier: u16,
    #[debug(format = "{:04x}")]
    pub sequence_number: u16,
}

impl Echo {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(tuple((be_u16, be_u16)),
            |(identifier, sequence_number)| {
                Echo {
                    identifier,
                    sequence_number,
                }
            }
        )(i)
    }
}

#[derive(Debug, Clone)]
pub enum Header {
    EchoRequest(Echo),
    EchoReply(Echo),
    Other(u32),
}

#[derive(CustomDebug, Clone)]
pub struct Packet {
    pub typ: Type,
    #[debug(skip)]
    pub checksum: u16,
    #[debug(format = "{:?}")]
    pub header: Header,
    pub payload: Blob,
}

impl Echo {
    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((
            be_u16(self.identifier),
            be_u16(self.sequence_number),
        ))
    }
}

impl Header {
    pub fn serialize_type_and_code<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u8, sequence::tuple};

        move |out| match self {
            Self::EchoRequest(_) => tuple((be_u8(8), be_u8(0)))(out),
            Self::EchoReply(_) => tuple((be_u8(0), be_u8(0)))(out),
            // we're not planning on sending any "TTL Expired" or
            // "Host unreachable" ICMP packets.
            _ => unimplemented!(),
        }
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::bytes::be_u32;

        move |out| {
             match self {
                Self::EchoRequest(e) | Self::EchoReply(e) => e.serialize()(out),
                Self::Other(x) => be_u32(*x)(out),
             }
        }
    }
}

impl Packet {
    pub fn echo_request<P: AsRef<[u8]>>(echo: Echo, payload: P) -> Self {
        Self {
            typ: Type::EchoRequest,
            checksum: 0,
            header: Header::EchoRequest(echo),
            payload: Blob::new(payload.as_ref()),
        }
    }

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, typ) = {
            let (i, (typ, code)) = tuple((be_u8, be_u8))(i)?;
            (i, Type::from((typ, code)))
        };
        let (i, checksum) = be_u16(i)?;
        let (i, header) = match typ {
            Type::EchoRequest => map(Echo::parse, Header::EchoRequest)(i)?,
            Type::EchoReply => map(Echo::parse, Header::EchoReply)(i)?,
            _ => map(be_u32, Header::Other)(i)?,
        };
        let payload = Blob::new(i);

        let packet = Self {
            typ,
            checksum,
            header,
            payload,
        };

        Ok((i, packet))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::le_u16, combinator::slice};

        move |out| {
            let mut buf = cf::gen_simple(self.serialize_no_checksum(), Vec::new())?;
            let checksum = ipv4::checksum(&buf);
            cf::gen_simple(le_u16(checksum), &mut buf[2..])?;

            slice(buf)(out)
        }
    }

    pub fn serialize_no_checksum<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((
            self.header.serialize_type_and_code(),
            be_u16(0), // checksum
            self.header.serialize(),
            self.payload.serialize(),
        ))
    }
}

impl From<(u8, u8)> for Type {
    fn from((typ, code): (u8, u8)) -> Self {
        match typ {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable(code.into()),
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded(code.into()),
            _ => Self::Other(typ, code),
        }
    }
}

impl From<u8> for DestinationUnreachable {
    fn from(x: u8) -> Self {
        match x {
            1 => Self::HostUnreachable,
            x => Self::Other(x),
        }
    }
}

impl From<u8> for TimeExceeded {
    fn from(x: u8) -> Self {
        match x {
            0 => Self::TTLExpired,
            x => Self::Other(x),
        }
    }
}