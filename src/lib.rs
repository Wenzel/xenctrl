extern crate xenctrl_sys;
use std::ptr::{null_mut};

pub struct Xc {
    handle: *mut xenctrl_sys::xc_interface,
}

impl Xc {

    pub fn new() -> Xc {
        let xc_handle = unsafe {
            let toto = xenctrl_sys::xc_interface_open(null_mut(), null_mut(), 0);
            toto
        };
        let xc = Xc { handle: xc_handle };
        xc
    }

    pub fn close(&mut self) {
        unsafe {
            xenctrl_sys::xc_interface_close(self.handle);
        };
        self.handle = std::ptr::null_mut();
    }
}
