pub mod consts;
pub mod error;
mod libxenctrl;

#[macro_use]
mod macros;

extern crate xenctrl_sys;

use std::{
    convert::TryInto,
    ffi,
    ffi::c_void,
    mem,
    ptr::{null_mut, NonNull},
};

use libxenctrl::LibXenCtrl;
use xenctrl_sys::{
    hvm_hw_cpu, xc_error_code, xc_interface, xen_pfn_t, xentoollog_logger, __HVM_SAVE_TYPE_CPU,
};

use error::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct XenControl {
    handle: NonNull<xc_interface>,
    libxenctrl: LibXenCtrl,
}

impl XenControl {
    pub fn new(
        logger: Option<&mut xentoollog_logger>,
        dombuild_logger: Option<&mut xentoollog_logger>,
        open_flags: u32,
    ) -> Result<Self> {
        let libxenctrl = unsafe { LibXenCtrl::new() };

        let xc_handle = (libxenctrl.interface_open)(
            logger.map_or_else(null_mut, |l| l as *mut _),
            dombuild_logger.map_or_else(null_mut, |l| l as *mut _),
            open_flags,
        );

        NonNull::new(xc_handle)
            .ok_or_else(|| {
                let desc = (libxenctrl.error_code_to_desc)(xc_error_code::XC_INTERNAL_ERROR as _);
                Error::new(unsafe { ffi::CStr::from_ptr(desc) }.to_str().unwrap())
            })
            .map(|handle| XenControl { handle, libxenctrl })
    }

    pub fn default() -> Result<Self> {
        Self::new(None, None, 0)
    }

    pub fn domain_hvm_getcontext_partial(&self, domid: u32, vcpu: u16) -> Result<hvm_hw_cpu> {
        let xc = self.handle.as_ptr();
        let mut hvm_cpu: hvm_hw_cpu =
            unsafe { mem::MaybeUninit::<hvm_hw_cpu>::zeroed().assume_init() };
        // cast to mut c_void*
        let hvm_cpu_ptr = &mut hvm_cpu as *mut _ as *mut c_void;
        // #define HVM_SAVE_CODE(_x) (sizeof (((struct __HVM_SAVE_TYPE_##_x *)(0))->c))
        let hvm_save_type_cpu =
            unsafe { mem::MaybeUninit::<__HVM_SAVE_TYPE_CPU>::zeroed().assume_init() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_type_cpu.c).try_into().unwrap();
        let hvm_size: u32 = mem::size_of::<hvm_hw_cpu>().try_into().unwrap();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_hvm_getcontext_partial)(
            xc,
            domid,
            hvm_save_code_cpu,
            vcpu,
            hvm_cpu_ptr,
            hvm_size,
        );
        last_error!(self, hvm_cpu)
    }

    pub fn monitor_enable(&mut self, domid: u32) -> Result<(*mut c_void, u32)> {
        let xc = self.handle.as_ptr();
        let mut remote_port: u32 = 0;
        (self.libxenctrl.clear_last_error)(xc);
        let ring_page: *mut c_void =
            (self.libxenctrl.monitor_enable)(xc, domid.try_into().unwrap(), &mut remote_port);
        last_error!(self, (ring_page, remote_port))
    }

    pub fn monitor_disable(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.monitor_disable)(xc, domid.try_into().unwrap());
        last_error!(self, ())
    }

    pub fn domain_pause(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_pause)(xc, domid);
        last_error!(self, ())
    }

    pub fn domain_unpause(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_unpause)(xc, domid);
        last_error!(self, ())
    }

    pub fn domain_maximum_gpfn(&self, domid: u32) -> Result<u64> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let mut max_gpfn: xen_pfn_t = unsafe { mem::MaybeUninit::zeroed().assume_init() };
        (self.libxenctrl.domain_maximum_gpfn)(xc, domid.try_into().unwrap(), &mut max_gpfn);
        last_error!(self, max_gpfn)
    }

    fn close(&mut self) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.interface_close)(xc);
        last_error!(self, ())
    }
}

impl Drop for XenControl {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}
