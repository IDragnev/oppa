use std::{
    fmt,
};
use custom_debug_derive::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Addr([u8; 6]);

impl Addr {
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 6 {
            let mut addr = Self([0; 6]);
            addr.0.copy_from_slice(&bytes[..6]);

            Some(addr)
        }
        else {
            None
        }
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

#[derive(CustomDebug)]
pub struct Frame {
    pub dst: Addr,
    pub src: Addr,

    #[debug(format = "0x{:04x}")]
    pub ether_type: u16,
}

impl Frame {
    pub fn parse(i: &[u8]) -> Self {
        let read_u16 = |slice: &[u8]| {
            let mut res = [0u8; 2];
            res.copy_from_slice(&slice[..2]);
            u16::from_be_bytes(res)
        };

        Self {
            dst: Addr::new(&i[0..6]).unwrap(),
            src: Addr::new(&i[6..12]).unwrap(),
            ether_type: read_u16(&i[12..]),
        }
    }
}