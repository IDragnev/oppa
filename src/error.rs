use std::fmt;

pub enum Error {
    Rawsock(rawsock::Error),
    IO(std::io::Error),
    Win32(u32),
}

impl From<rawsock::Error> for Error {
    fn from(e: rawsock::Error) -> Self {
        Self::Rawsock(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Rawsock(e) => write!(f, "Rawsock error code {}", e),
            Self::IO(e) => write!(f, "IO error code {}", e),
            Self::Win32(e) => write!(f, "Win32 error code {} (0x{:x})", e, e),
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for Error {}