macro_rules! last_error {
    ($self:expr, $ok:expr) => {
        unsafe {
            let err = ($self.libxenctrl.get_last_error)($self.handle.as_ptr());
            match (*err).code {
                xc_error_code::XC_ERROR_NONE => Ok($ok),
                code => {
                    let desc = ($self.libxenctrl.error_code_to_desc)(code as _);
                    Err(XcError::new(ffi::CStr::from_ptr(desc).to_str().unwrap()))
                }
            }
        }
    };
}
