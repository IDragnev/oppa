use bitvec::prelude::*;
use cookie_factory as cf;
use std::{
    io,
    cmp::{
        min,
    },
};
use ux::*;

pub type BitOutput = BitVec<u8, Msb0>;

pub fn bits<W, F>(f: F) -> impl cf::SerializeFn<W>
where
    W: io::Write,
    F: Fn(&mut BitOutput),
{
    move |mut out: cf::WriteContext<W>| {
        let mut bo = BitOutput::new();
        f(&mut bo);
        io::Write::write(&mut out, bo.as_raw_slice())?;

        Ok(out)
    }
}

pub trait WriteLastNBits {
    fn write_last_n_bits<B: BitStore>(&mut self, b: B, num_bits: usize);
}

impl WriteLastNBits for BitOutput {
    fn write_last_n_bits<B: BitStore>(&mut self, b: B, num_bits: usize) {
        let bitslice = b.view_bits::<Msb0>();
        let num_bits = min(bitslice.len(), num_bits);
        let start = bitslice.len() - num_bits;
        self.extend_from_bitslice(&bitslice[start..])
    }
}

pub trait BitSerialize {
    fn write(&self, b: &mut BitOutput);
}

macro_rules! impl_bit_serialize_for_ux {
    ($($width: expr),*) => {
        $(
            paste::item! {
                impl BitSerialize for [<u $width>] {
                    fn write(&self, b: &mut BitOutput) {
                        b.write_last_n_bits(u16::from(*self), $width);
                    }
                }
            }
        )*
    };
}

impl_bit_serialize_for_ux!(2, 3, 4, 6, 13);