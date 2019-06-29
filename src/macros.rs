macro_rules! last_error {
    ($xc:expr, $ok:expr) => {
        unsafe {
            let err = xc_get_last_error($xc);
            match (*err).code {
                xc_error_code::XC_ERROR_NONE => Ok($ok),
                code => Err(Error::new(code)),
            }
        }
    };
}
