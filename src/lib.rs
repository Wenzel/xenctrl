extern crate xenctrl_sys;
use std::ptr::{null_mut};

struct Xc {
    handle: *mut xenctrl_sys::xc_interface,
}

impl Xc {

    pub fn new(&mut self) {
        self.handle = unsafe {
            let toto = xenctrl_sys::xc_interface_open(null_mut(), null_mut(), 0);
            toto
        };
    }
}

// close
impl Drop for Xc {

    fn drop(&mut self) {
        unsafe {
            xenctrl_sys::xc_interface_close(self.handle);
        };
    }
}
