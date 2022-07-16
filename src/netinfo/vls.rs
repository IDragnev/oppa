use std::{
    mem,
    ptr,
    marker::PhantomData,
    ops::Deref,
    ops::DerefMut,
};
use crate::{
    error::Error,
};

pub struct VLS<T> {
    data: Vec<u8>,
    _phantom: PhantomData<T>
}

impl<T> VLS<T> {
    pub fn new<F>(f: F) -> Result<Self, Error>
        where F: Fn(*mut T, *mut u32) -> u32,
    {
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;

        let mut size = 0;
        match f(ptr::null_mut(), &mut size) {
            ERROR_INSUFFICIENT_BUFFER => {},
            ERROR_BUFFER_OVERFLOW  => {},
            ret => return Err(Error::Win32(ret)),
        };

        let mut v = vec![0u8; size as usize];
        match f(unsafe { mem::transmute(v.as_mut_ptr()) }, &mut size) {
            0 => {}
            r => return Err(Error::Win32(r)),
        };

        Ok(Self {
            data: v,
            _phantom: PhantomData::default(),
        })
    }
}

impl<T> Deref for VLS<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { mem::transmute(self.data.as_ptr()) }
    }
}

impl<T> DerefMut for VLS<T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { mem::transmute(self.data.as_ptr()) }
    }
}