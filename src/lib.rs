extern crate xenctrl_sys;
use std::io::Error;
use std::ptr::{null_mut};
use std::os::raw::{c_void};

pub struct Xc {
    handle: *mut xenctrl_sys::xc_interface,
    evtchn_port: *mut u32,
}

impl Xc {

    pub fn new() -> Result<Self,Error> {
        let xc_handle = unsafe {
            let result = xenctrl_sys::xc_interface_open(null_mut(), null_mut(), 0);
            result
        };
        if xc_handle == null_mut() {
            return Err(Error::last_os_error());
        }
        return Ok(Xc {
            handle: xc_handle,
            evtchn_port: null_mut()
        });
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

    pub fn close(&mut self) -> Result<(),&str>{
        let result = unsafe {
            let result = xenctrl_sys::xc_interface_close(self.handle);
            result
        };
        match result {
            0 => return Ok(()),
            -1 => return Err("Fail to close xc interface"),
            _ => panic!("unexpected value"),
        }
    }
}
