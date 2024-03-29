use std::{
    cmp::min,
    fmt,
    io,
};
use cookie_factory as cf;

#[derive(Clone)]
pub struct Blob(pub Vec<u8>);

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let slice_len = self.0.len();
        let shown_len = 20;
        let slice = &self.0[..min(shown_len, slice_len)];

        write!(f, "[")?;
        for (i, x) in slice.iter().enumerate() {
            let prefix = if i > 0 { " " } else { "" };
            write!(f, "{}{:02x}", prefix, x)?;
        }
        if slice_len > shown_len {
            write!(f, " + {} bytes", slice_len - shown_len)?;
        }
        write!(f, "]")
    }
}

impl Blob {
    pub fn new(slice: &[u8]) -> Self {
        Self(slice.into())
    }

    pub fn serialize<'a, W: io::Write + 'a>(&'a self) -> impl cf::SerializeFn<W> + 'a {
        use cookie_factory::combinator::slice;
        slice(&self.0)
    }
}