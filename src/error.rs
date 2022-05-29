use crate::netinfo;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Raw socket error: {0}")]
    Rawsock(#[from] rawsock::Error),
    #[error("I/O: {0}")]
    IO(#[from] std::io::Error),
    #[error("Win32 error code {0} (0x{0:x})")]
    Win32(u32),
    #[error("NetInfo error: {0}")]
    NetInfo(#[from] netinfo::Error),
}