pub mod error;
pub mod consts;

#[macro_use]
mod macros;

extern crate xenctrl_sys;

use std::{
    mem,
    ptr::{null_mut, NonNull},
    ffi::c_void,
    convert::TryInto,
};

use xenctrl_sys::{
    xc_clear_last_error, xc_domain_maximum_gpfn, xc_domain_pause, xc_domain_unpause, xc_error_code,
    xc_get_last_error, xc_interface, xc_interface_close, xc_interface_open, xc_monitor_disable,
    xc_monitor_enable, xentoollog_logger, xc_domain_hvm_getcontext_partial, hvm_hw_cpu,
    __HVM_SAVE_TYPE_CPU,
};

use error::Error;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct XenControl {
    handle: NonNull<xc_interface>,
}

impl XenControl {
    pub fn new(
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
            })
    }

    pub fn default() -> Result<Self> {
        Self::new(None, None, 0)
    }

    pub fn domain_hvm_getcontext_partial(&self, domid: u32, vcpu: u16) -> Result<hvm_hw_cpu> {
        let xc = self.handle.as_ptr();
        let mut hvm_cpu: hvm_hw_cpu = unsafe { mem::MaybeUninit::<hvm_hw_cpu>::zeroed().assume_init() };
        // cast to mut c_void*
        let hvm_cpu_ptr = &mut hvm_cpu as *mut _ as *mut c_void;
        // #define HVM_SAVE_CODE(_x) (sizeof (((struct __HVM_SAVE_TYPE_##_x *)(0))->c))
        let hvm_save_type_cpu = unsafe { mem::MaybeUninit::<__HVM_SAVE_TYPE_CPU>::zeroed().assume_init() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_type_cpu.c).try_into().unwrap();
        let hvm_size: u32 = mem::size_of::<hvm_hw_cpu>().try_into().unwrap();
        unsafe {
            xc_clear_last_error(xc);
            xc_domain_hvm_getcontext_partial(xc, domid, hvm_save_code_cpu, vcpu, hvm_cpu_ptr, hvm_size)
        };
        last_error!(xc, hvm_cpu)
    }

    pub fn monitor_enable(&mut self, domid: u32) -> Result<(*mut c_void, u32)> {
        let xc = self.handle.as_ptr();
        let domid_compat: u16 = domid.try_into().unwrap();
        let mut remote_port: u32 = 0;
        let ring_page: *mut c_void = unsafe {
            xc_clear_last_error(xc);
            xc_monitor_enable(xc, domid_compat, &mut remote_port)
        };
        last_error!(xc, (ring_page, remote_port))
    }

    pub fn monitor_disable(&self, domid: u32) -> Result<()> {
        let xc = self.handle.as_ptr();
        unsafe {
            xc_clear_last_error(xc);
            xc_monitor_disable(xc, domid.try_into().unwrap());
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
        let mut max_gpfn = mem::MaybeUninit::<u64>::uninit();
        unsafe {
            max_gpfn = mem::MaybeUninit::zeroed().assume_init();
            xc_clear_last_error(xc);
            xc_domain_maximum_gpfn(xc, domid.try_into().unwrap(), max_gpfn.as_mut_ptr());
        }
        last_error!(xc, max_gpfn.assume_init())
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
