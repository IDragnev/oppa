use std::{
    fmt,
    num::ParseIntError,
};

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Addr(pub [u8; 4]);

#[derive(Debug)]
pub enum ParseAddrError {
    TooManyOctets,
    InsufficientOctets,
    InvalidOctet(ParseIntError),
}

impl Addr {
    pub fn parse(s: &str) -> Result<Self, ParseAddrError> {
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

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{}.{}.{}.{}", a, b, c, d)
    }
}

impl fmt::Display for ParseAddrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ParseAddrError {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_addr_with_insufficient_octets_fails() {
        assert!(matches!(Addr::parse("8"), Err(ParseAddrError::InsufficientOctets)));
        assert!(matches!(Addr::parse("8.8"), Err(ParseAddrError::InsufficientOctets)));
        assert!(matches!(Addr::parse("8.8.8"), Err(ParseAddrError::InsufficientOctets)));
    }

    #[test]
    fn parse_addr_with_too_many_octets_fails() {
        assert!(matches!(Addr::parse("8.8.8.8.8"), Err(ParseAddrError::TooManyOctets)));
    }

    #[test]
    fn parse_addr_with_invalid_octet_fails() {
        assert!(matches!(Addr::parse(""), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::parse("8."), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::parse("8.x.8.8"), Err(ParseAddrError::InvalidOctet(_))));
        assert!(matches!(Addr::parse("8.256.8.8"), Err(ParseAddrError::InvalidOctet(_))));
    }

    #[test]
    fn parse_addr_with_correct_addres_is_ok() {
        assert!(matches!(Addr::parse("8.8.8.8"), Ok(_)));
    }
}