use std::{
    error, ffi,
    fmt::{self, Debug, Display, Formatter},
};

use xenctrl_sys::{xc_error_code, xc_error_code_to_desc};

#[derive(Copy, Clone)]
pub struct Error(xc_error_code);

impl Error {
    pub fn new(code: xc_error_code) -> Self {
        Self(code)
    }

    pub fn desc(self) -> &'static str {
        unsafe {
            let desc = xc_error_code_to_desc(self.0 as _);
            ffi::CStr::from_ptr(desc).to_str().unwrap()
        }
    }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.desc())
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.desc())
    }
}

impl error::Error for Error {}
