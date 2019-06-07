extern crate xenctrl_sys;
use std::ptr::{null_mut};
use std::os::raw::{c_void};

pub struct Xc {
    handle: *mut xenctrl_sys::xc_interface,
    evtchn_port: *mut u32,
}

impl Xc {

    pub fn new() -> Self {
        let xc_handle = unsafe {
            let toto = xenctrl_sys::xc_interface_open(null_mut(), null_mut(), 0);
            toto
        };
        let xc = Xc { handle: xc_handle, evtchn_port: null_mut() };
        xc
    }

    pub fn monitor_enable(&self, domid: u32) -> *mut c_void {
        let ring_page = unsafe {
            let toto = xenctrl_sys::xc_monitor_enable(self.handle, domid, self.evtchn_port);
            toto
        };
        ring_page
    }

    pub fn monitor_disable(&self, domid: u32) {
        unsafe {
            xenctrl_sys::xc_monitor_disable(self.handle, domid);
        };
    }

    pub fn domain_pause(&self, domid: u32) -> Result<(),&str> {
        unsafe {
            match xenctrl_sys::xc_domain_pause(self.handle, domid) {
                0 => return Ok(()),
                -1 => return Err("Fail to pause domain"),
                _ => panic!("unexpected value"),
            }
        };
    }

    pub fn domain_unpause(&self, domid: u32) -> Result<(),&str> {
        unsafe {
            match xenctrl_sys::xc_domain_unpause(self.handle, domid) {
                0 => return Ok(()),
                -1 => return Err("Fail to unpause domain"),
                _ => panic!("unexpected value"),
            }
        };
    }

    pub fn close(&mut self) {
        unsafe {
            xenctrl_sys::xc_interface_close(self.handle);
        };
        self.handle = std::ptr::null_mut();
    }
}
