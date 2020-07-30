pub mod consts;
pub mod error;
mod libxenctrl;

#[macro_use]
mod macros;

extern crate xenctrl_sys;

use self::consts::PAGE_SIZE;
use enum_primitive_derive::Primitive;
use libxenctrl::LibXenCtrl;
use num_traits::FromPrimitive;
use std::io::Error;
use std::{
    alloc::{alloc_zeroed, Layout},
    convert::TryInto,
    ffi,
    ffi::c_void,
    mem,
    os::raw::c_uint,
    ptr::{null_mut, NonNull},
};
pub use xenctrl_sys::{hvm_hw_cpu, hvm_save_descriptor, __HVM_SAVE_TYPE_CPU};
use xenctrl_sys::{xc_error_code, xc_interface, xenmem_access_t, xentoollog_logger};
use xenvmevent_sys::{
    vm_event_back_ring, vm_event_request_t, vm_event_response_t, vm_event_sring,
    VM_EVENT_REASON_WRITE_CTRLREG,
};

use error::XcError;

type Result<T> = std::result::Result<T, XcError>;

#[derive(Primitive, Debug, Copy, Clone, PartialEq)]
pub enum XenCr {
    Cr0 = 0,
    Cr3 = 1,
    Cr4 = 2,
}

#[derive(Debug, Copy, Clone)]
pub enum XenEventType {
    Cr {
        cr_type: XenCr,
        new: u64,
        old: u64,
    },
    Msr {
        msr_type: u32,
        new: u64,
        old: u64,
    },
    Breakpoint {
        gpa: u64,
        insn_len: u8,
    },
    Pagefault {
        gva: u64,
        gpa: u64,
        access: xenmem_access_t,
        view: u16,
    },
}

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

        #[allow(clippy::redundant_closure)]
        let xc_handle = (libxenctrl.interface_open)(
            logger.map_or_else(|| null_mut(), |l| l as *mut _),
            dombuild_logger.map_or_else(|| null_mut(), |l| l as *mut _),
            open_flags,
        );

        NonNull::new(xc_handle)
            .ok_or_else(|| {
                let desc = (libxenctrl.error_code_to_desc)(xc_error_code::XC_INTERNAL_ERROR as _);
                XcError::new(unsafe { ffi::CStr::from_ptr(desc) }.to_str().unwrap())
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
        let hvm_size: u32 = mem::size_of::<hvm_hw_cpu>().try_into().unwrap();
        let hvm_save_cpu =
            unsafe { mem::MaybeUninit::<__HVM_SAVE_TYPE_CPU>::zeroed().assume_init() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_cpu.c).try_into().unwrap();

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

    pub fn domain_hvm_setcontext(
        &self,
        domid: u32,
        buffer: *mut c_uint,
        size: usize,
    ) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_hvm_setcontext)(xc, domid, buffer, size.try_into().unwrap());
        last_error!(self, ())
    }

    pub fn domain_hvm_getcontext(
        &self,
        domid: u32,
        vcpu: u16,
    ) -> Result<(*mut c_uint, hvm_hw_cpu, u32)> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let size =
            (self.libxenctrl.domain_hvm_getcontext)(xc, domid, std::ptr::null_mut::<u32>(), 0);
        let layout =
            Layout::from_size_align(size.try_into().unwrap(), mem::align_of::<u8>()).unwrap();
        #[allow(clippy::cast_ptr_alignment)]
        let buffer = unsafe { alloc_zeroed(layout) as *mut c_uint };
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_hvm_getcontext)(xc, domid, buffer, size.try_into().unwrap());
        let mut offset: u32 = 0;
        let hvm_save_cpu =
            unsafe { mem::MaybeUninit::<__HVM_SAVE_TYPE_CPU>::zeroed().assume_init() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_cpu.c).try_into().unwrap();
        let mut cpu_ptr: *mut hvm_hw_cpu = std::ptr::null_mut();
        unsafe {
            while offset < size.try_into().unwrap() {
                let buffer_ptr = buffer as usize;
                let descriptor: *mut hvm_save_descriptor =
                    (buffer_ptr + offset as usize) as *mut hvm_save_descriptor;
                let diff: u32 = mem::size_of::<hvm_save_descriptor>().try_into().unwrap();
                offset += diff;
                if (*descriptor).typecode == hvm_save_code_cpu && (*descriptor).instance == vcpu {
                    cpu_ptr = (buffer_ptr + offset as usize) as *mut hvm_hw_cpu;
                    break;
                }

                offset += (*descriptor).length;
            }
        }
        last_error!(self, (buffer, *cpu_ptr, size.try_into().unwrap()))
    }

    pub fn monitor_enable(
        &mut self,
        domid: u32,
    ) -> Result<(vm_event_sring, vm_event_back_ring, u32)> {
        let xc = self.handle.as_ptr();
        let mut remote_port: u32 = 0;
        (self.libxenctrl.clear_last_error)(xc);
        let void_ring_page: *mut c_void =
            (self.libxenctrl.monitor_enable)(xc, domid.try_into().unwrap(), &mut remote_port);
        let ring_page = void_ring_page as *mut vm_event_sring;
        unsafe {
            (*ring_page).req_prod = 0;
            (*ring_page).rsp_prod = 0;
            (*ring_page).req_event = 1;
            (*ring_page).rsp_event = 1;
            (*ring_page).pvt.pvt_pad = mem::MaybeUninit::zeroed().assume_init();
            (*ring_page).__pad = mem::MaybeUninit::zeroed().assume_init();
        }
        // BACK_RING_INIT(&back_ring, ring_page, XC_PAGE_SIZE);
        let mut back_ring: vm_event_back_ring =
            unsafe { mem::MaybeUninit::<vm_event_back_ring>::zeroed().assume_init() };
        back_ring.rsp_prod_pvt = 0;
        back_ring.req_cons = 0;
        back_ring.nr_ents = __RING_SIZE!(ring_page, PAGE_SIZE);
        back_ring.sring = ring_page;
        last_error!(self, (*ring_page, back_ring, remote_port))
    }

    pub fn get_request(&self, back_ring: &mut vm_event_back_ring) -> Result<vm_event_request_t> {
        let req_init = unsafe { mem::MaybeUninit::<vm_event_request_t>::zeroed().assume_init() };
        let req_slice: &mut [vm_event_request_t] = &mut [req_init];
        let mut req_cons = back_ring.req_cons;
        let req_from_ring = RING_GET_REQUEST!(back_ring, req_cons);
        let req_from_ring_slice = unsafe { std::slice::from_raw_parts(req_from_ring, 1) };
        req_slice[0..].copy_from_slice(&req_from_ring_slice[0..1]);
        req_cons += 1;
        back_ring.req_cons = req_cons;
        unsafe {
            (*(back_ring.sring)).req_event = 1 + req_cons;
        }
        last_error!(self, (*req_slice)[0])
    }

    pub fn put_response(
        &self,
        rsp: &mut vm_event_response_t,
        back_ring: &mut vm_event_back_ring,
    ) -> Result<()> {
        let rsp_slice = unsafe { std::slice::from_raw_parts(rsp, 1) };
        let mut rsp_prod = back_ring.rsp_prod_pvt;
        let rsp_from_ring = RING_GET_RESPONSE!(back_ring, rsp_prod);
        let rsp_from_ring_slice = unsafe { std::slice::from_raw_parts_mut(rsp_from_ring, 1) };
        rsp_from_ring_slice[0..].copy_from_slice(&rsp_slice[0..1]);
        rsp_prod += 1;
        back_ring.rsp_prod_pvt = rsp_prod;
        RING_PUSH_RESPONSES!(back_ring);
        last_error!(self, ())
    }

    pub fn get_event_type(&self, req: vm_event_request_t) -> Result<XenEventType> {
        let ev_type: XenEventType;
        unsafe {
            ev_type = match req.reason {
                VM_EVENT_REASON_WRITE_CTRLREG => XenEventType::Cr {
                    cr_type: XenCr::from_i32(req.u.write_ctrlreg.index.try_into().unwrap())
                        .unwrap(),
                    new: req.u.write_ctrlreg.new_value,
                    old: req.u.write_ctrlreg.old_value,
                },
                _ => unimplemented!(),
            };
        }
        last_error!(self, ev_type)
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

    pub fn monitor_software_breakpoint(&self, domid: u32, enable: bool) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_software_breakpoint)(xc, domid, enable);
        if rc < 0 {
            println!("last OS error: {:?}", Error::last_os_error());
        }
        last_error!(self, ())
    }

    pub fn monitor_mov_to_msr(&self, domid: u32, msr: u32, enable: bool) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_mov_to_msr)(xc, domid.try_into().unwrap(), msr, enable);
        if rc < 0 {
            println!("last OS error: {:?}", Error::last_os_error());
        }
        last_error!(self, ())
    }

    pub fn monitor_write_ctrlreg(
        &self,
        domid: u32,
        index: XenCr,
        enable: bool,
        sync: bool,
        onchangeonly: bool,
    ) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_write_ctrlreg)(
            xc,
            domid.try_into().unwrap(),
            index as u16,
            enable,
            sync,
            onchangeonly,
        );
        if rc < 0 {
            println!("last OS error: {:?}", Error::last_os_error());
        }
        last_error!(self, ())
    }

    pub fn set_mem_access(
        &self,
        domid: u32,
        access: xenmem_access_t,
        first_pfn: u64,
        nr: u32,
    ) -> Result<()> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.set_mem_access)(xc, domid.try_into().unwrap(), access, first_pfn, nr);
        last_error!(self, ())
    }

    pub fn get_mem_access(&self, domid: u32, pfn: u64) -> Result<xenmem_access_t> {
        let xc = self.handle.as_ptr();
        let access: *mut xenmem_access_t = std::ptr::null_mut();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.get_mem_access)(xc, domid.try_into().unwrap(), pfn, access);
        last_error!(self, *access)
    }

    pub fn domain_maximum_gpfn(&self, domid: u32) -> Result<u64> {
        let xc = self.handle.as_ptr();
        #[allow(unused_assignments)]
        let mut max_gpfn = mem::MaybeUninit::<u64>::uninit();
        (self.libxenctrl.clear_last_error)(xc);
        unsafe {
            max_gpfn = mem::MaybeUninit::zeroed().assume_init();
        }
        (self.libxenctrl.domain_maximum_gpfn)(xc, domid.try_into().unwrap(), max_gpfn.as_mut_ptr());
        last_error!(self, max_gpfn.assume_init())
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
