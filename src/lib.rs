pub mod error;
pub mod support;

#[macro_use]
mod macros;

extern crate xenctrl_sys;
use std::{
    mem,
    ptr::{null_mut, NonNull},
};

use xenctrl_sys::{
    xc_clear_last_error, xc_domain_maximum_gpfn, xc_domain_pause, xc_domain_unpause, xc_error_code,
    xc_get_last_error, xc_interface, xc_interface_close, xc_interface_open, xc_monitor_disable,
    xc_monitor_enable, xentoollog_logger,
};

use error::Error;
use support::PageInfo;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct XenControl {
    handle: NonNull<xc_interface>,
    evtchn_port: u32,
}

impl XenControl {
    pub fn from(
        logger: Option<&mut xentoollog_logger>,
        dombuild_logger: Option<&mut xentoollog_logger>,
        open_flags: u32,
    ) -> Result<Self> {
        let xc_handle = unsafe {
            xc_interface_open(
                logger.map_or_else(|| null_mut(), |l| l as *mut _),
                dombuild_logger.map_or_else(|| null_mut(), |l| l as *mut _),
                open_flags,
            )
        };

        NonNull::new(xc_handle)
            .ok_or_else(|| Error::new(xc_error_code::XC_INTERNAL_ERROR))
            .map(|handle| XenControl {
                handle,
                evtchn_port: 0u32,
            })
    }

    pub fn default() -> Result<Self> {
        Self::from(None, None, 0)
    }

    pub fn monitor_enable(&mut self, domid: u32) -> Result<&PageInfo> {
        let xc = self.handle.as_ptr();
        let ring_page = unsafe {
            xc_clear_last_error(xc);
            xc_monitor_enable(xc, domid, &mut self.evtchn_port as _) as *const PageInfo
        };
        last_error!(xc, &*ring_page)
    }

    pub fn monitor_disable(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        unsafe {
            xc_clear_last_error(xc);
            xc_monitor_disable(xc, domid);
        };
        last_error!(xc, ())
    }

    pub fn domain_pause(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        unsafe {
            xc_clear_last_error(xc);
            xc_domain_pause(xc, domid);
        };
        last_error!(xc, ())
    }

    pub fn domain_unpause(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        unsafe {
            xc_clear_last_error(xc);
            xc_domain_unpause(xc, domid);
        }
        last_error!(xc, ())
    }

    pub fn domain_maximum_gpfn(&self, domid: u32) -> Result<u64> {
        let xc = self.handle.as_ptr();
        let mut max_gpfn: u64;
        unsafe {
            max_gpfn = mem::uninitialized();
            xc_clear_last_error(xc);
            xc_domain_maximum_gpfn(xc, domid, &mut max_gpfn as _);
        }
        last_error!(xc, max_gpfn)
    }

    fn close(&mut self) -> Result<()> {
        let xc = self.handle.as_ptr();
        unsafe {
            xc_clear_last_error(xc);
            xc_interface_close(xc);
        }
        last_error!(xc, ())
    }
}

impl Drop for XenControl {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}
