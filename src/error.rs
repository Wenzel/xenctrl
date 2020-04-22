use std::{
    error,
    fmt::{self, Debug, Display, Formatter},
};

pub struct Error {
    desc: String,
}

impl Error {
    pub fn new(s: &str) -> Self {
        Self { desc: s.to_owned() }
    }

    // TODO: call xc_error_code_to_desc using libxenctrl
    // pub fn desc(self) -> &'static str {
    //     unsafe {
    //         let desc = xc_error_code_to_desc(self.0 as _);
    //         ffi::CStr::from_ptr(desc).to_str().unwrap()
    //     }
    // }
}

impl Display for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.desc)
    }
}

impl Debug for Error {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.desc)
    }
}

impl error::Error for Error {}
