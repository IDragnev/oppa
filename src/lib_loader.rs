use std::{
    ffi::{
        c_void,
        CString,
    },
    os::raw::{
        c_char,
    },
    mem::transmute_copy,
    ptr::self,
};

type FarProc = ptr::NonNull<c_void>;
type HModule = ptr::NonNull<c_void>;
extern "stdcall" {
    fn LoadLibraryA(name: *const c_char) -> Option<HModule>;
    fn GetProcAddress(module: HModule, name: *const c_char) -> Option<FarProc>;
}

#[derive(Debug)]
pub struct Library {
    name: String,
    module: HModule,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum LoadLibError {
    #[error("could not open library {0:?}")]
    NotFound(String),
    #[error("invalid library name: {0:?}")]
    InvalidName(#[from] std::ffi::NulError),
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum GetProcError {
    #[error("could not find proc {proc:?} in {lib:?}")]
    NotFound{ proc: String, lib: String },
    #[error("invalid proc name: {0:?}")]
    InvalidName(#[from] std::ffi::NulError),
}

impl Library {
    pub fn new(name: &str) -> Result<Self, LoadLibError> {
        let c_name = CString::new(name)?;
        let l = unsafe { LoadLibraryA(c_name.as_ptr()) };

        l.map(|module| Library { name: name.to_owned(), module })
         .ok_or(LoadLibError::NotFound(name.to_owned()))
    }

    pub fn get_proc<T>(&self, name: &str) -> Result<T, GetProcError> {
        let c_name = CString::new(name)?;
        let proc = unsafe { GetProcAddress(self.module, c_name.as_ptr()) };

        proc.map(|p| unsafe { transmute_copy(&p) })
            .ok_or(GetProcError::NotFound {
                proc: name.to_owned(),
                lib: self.name.clone()
            })
    }
}

#[macro_export]
macro_rules! bind {
    (library $lib:expr; $(fn $name:ident($($arg:ident: $type:ty),*) -> $ret:ty;)*) => {
        struct Functions {
            $(pub $name: extern "stdcall" fn ($($arg: $type),*) -> $ret),*
        }

        static FUNCTIONS: once_cell::sync::Lazy<Functions> =
            once_cell::sync::Lazy::new(|| {
                let lib = crate::lib_loader::Library::new($lib).unwrap();
                Functions {
                    $($name: lib.get_proc(stringify!($name)).unwrap()),*
                }
            });

        $(
            #[inline(always)]
            pub fn $name($($arg: $type),*) -> $ret {
                (FUNCTIONS.$name)($($arg),*)
            }
        )*
    };
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_DLL_NAME: &str = "IPHLPAPI.dll";

    #[test]
    fn load_lib_invalid_name() {
        let l = Library::new("name\0abcd");
        assert!(matches!(l, Err(LoadLibError::InvalidName(_))));
    }

    #[test]
    fn load_lib_non_existing_lib() {
        let l = Library::new("non_existing_lib_name");
        assert!(matches!(l, Err(LoadLibError::NotFound(_))));
    }

    #[test]
    fn load_lib_ok() {
        assert!(Library::new(TEST_DLL_NAME).is_ok());
    }

    #[test]
    fn get_proc_non_existent() {
        let l = Library::new(TEST_DLL_NAME).unwrap();
        let p = l.get_proc::<fn() -> ()>("NoSuchProcName");
        assert!(matches!(p, Err(GetProcError::NotFound{ proc: _, lib: _ })));
    }
    
    #[test]
    fn get_proc_invalid_name() {
        let l = Library::new(TEST_DLL_NAME).unwrap();
        let p = l.get_proc::<fn() -> ()>("proc\0name");
        assert!(matches!(p, Err(GetProcError::InvalidName(_))));
    }

    #[test]
    fn get_proc_ok() {
        let l = Library::new("IPHLPAPI.dll").unwrap();
        let p = l.get_proc::<extern "stdcall" fn() -> *const c_void>("IcmpCreateFile");
        assert!(p.is_ok());
    }
}