use crate::{
    ethernet,
    ipv4,
    parse,
    netinfo,
};
use derive_try_from_primitive::*;
use nom::{
    error::context,
    number::complete::be_u16,
    number::complete::be_u8,
    sequence::tuple,
};
use cookie_factory as cf;
use std::io;

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum Operation {
    Request = 1,
    Reply = 2,
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum HardwareType {
    Ethernet = 1,
}

#[derive(Debug)]
pub struct Packet {
    pub operation: Operation,
    pub sender_hw_addr: ethernet::Addr,
    pub sender_ip_addr: ipv4::Addr,
    pub target_hw_addr: ethernet::Addr,
    pub target_ip_addr: ipv4::Addr,
}

impl Packet {
    pub fn request(nic: &netinfo::NIC) -> Self {
        Self {
            operation: Operation::Request,
            sender_hw_addr: nic.phy_address,
            sender_ip_addr: nic.address,
            target_hw_addr: ethernet::Addr::zero(),
            target_ip_addr: nic.gateway,
        }
    }
}

impl Operation {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        let (i, op) = context("Operation", be_u16)(i)?;

        match Self::try_from(op) {
            Ok(x) => Ok((i, Some(x))),
            Err(_) => Ok((i, None)),
        }
    }
}

impl HardwareType {
    pub fn parse(i: parse::Input) -> parse::Result<Option<Self>> {
        let (i, x) = context("HardwareType", be_u16)(i)?;

        match Self::try_from(x) {
            Ok(typ) => Ok((i, Some(typ))),
            Err(_) => Ok((i, None)),
        }
    }
}

impl Packet {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let original_i = i;

        let (i, (htype, ptype, _hlen, _plen)) = tuple((
            HardwareType::parse,
            ethernet::EtherType::parse,
            be_u8,
            be_u8,
        ))(i)?;

        if let Some(HardwareType::Ethernet) = htype {
            // good!
        } else {
            let msg = "arp: only Ethernet is supported".into();
            return Err(nom::Err::Error(parse::Error::custom(original_i, msg)));
        }

        if let Some(ethernet::EtherType::IPv4) = ptype {
            // good!
        } else {
            let msg = "arp: only IPv4 is supported".into();
            return Err(nom::Err::Error(parse::Error::custom(original_i, msg)));
        }

        let (i, operation) = Operation::parse(i)?;
        let operation = match operation {
            Some(operation) => operation,
            _ => {
                let msg = "arp: only Request and Reply operations are supported".into();
                return Err(nom::Err::Error(parse::Error::custom(original_i, msg)));
            }
        };

        let (i, (sender_hw_addr, sender_ip_addr)) =
            tuple((ethernet::Addr::parse, ipv4::Addr::parse))(i)?;

        let (i, (target_hw_addr, target_ip_addr)) =
            tuple((ethernet::Addr::parse, ipv4::Addr::parse))(i)?;

        let res = Self {
            operation,
            sender_hw_addr,
            sender_ip_addr,
            target_hw_addr,
            target_ip_addr,
        };
        Ok((i, res))
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::{bytes::be_u8, sequence::tuple};

        let htype = HardwareType::Ethernet.serialize();
        let ptype = ethernet::EtherType::IPv4.serialize();
        let hlen = be_u8(6);
        let plen = be_u8(4);
        tuple((
            htype,
            ptype,
            hlen,
            plen,
            self.operation.serialize(),
            self.sender_hw_addr.serialize(),
            self.sender_ip_addr.serialize(),
            self.target_hw_addr.serialize(),
            self.target_ip_addr.serialize(),
        ))
    }
}

impl Operation {
    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::bytes::be_u16;
        be_u16(*self as u16)
    }
}

impl HardwareType {
    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cf::bytes::be_u16;
        be_u16(*self as u16)
    }
}