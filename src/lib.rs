pub mod consts;
pub mod error;
mod libxenctrl;

#[macro_use]
mod macros;

extern crate xenctrl_sys;

use self::consts::{PAGE_SHIFT, PAGE_SIZE};
use enum_primitive_derive::Primitive;
use error::XcError;
use libxenctrl::LibXenCtrl;
use num_traits::FromPrimitive;
use std::io::Error;
use std::{
    alloc::{alloc_zeroed, Layout},
    convert::{From, TryFrom, TryInto},
    ffi,
    ffi::c_void,
    mem,
    os::raw::c_uint,
    ptr::{null_mut, NonNull},
    slice,
};
pub use xenctrl_sys::{hvm_hw_cpu, hvm_save_descriptor, __HVM_SAVE_TYPE_CPU};
use xenctrl_sys::{xc_error_code, xc_interface, xenmem_access_t, xentoollog_logger};
use xenvmevent_sys::{
    vm_event_back_ring, vm_event_request_t, vm_event_response_t, vm_event_sring, MEM_ACCESS_R,
    MEM_ACCESS_RW, MEM_ACCESS_RWX, MEM_ACCESS_RX, MEM_ACCESS_W, MEM_ACCESS_WX, MEM_ACCESS_X,
    VM_EVENT_REASON_MEM_ACCESS, VM_EVENT_REASON_MOV_TO_MSR, VM_EVENT_REASON_SOFTWARE_BREAKPOINT,
    VM_EVENT_REASON_WRITE_CTRLREG, VM_EVENT_X86_CR0, VM_EVENT_X86_CR3, VM_EVENT_X86_CR4,
};

#[derive(Copy, Clone, Debug)]
#[repr(u32)]
pub enum XenPageAccess {
    NIL,
    R,
    W,
    RW,
    X,
    RX,
    WX,
    RWX,
}

impl TryFrom<u32> for XenPageAccess {
    type Error = &'static str;
    fn try_from(flag: u32) -> Result<Self, Self::Error> {
        match flag {
            0 => Ok(XenPageAccess::NIL),
            MEM_ACCESS_R => Ok(XenPageAccess::R),
            MEM_ACCESS_W => Ok(XenPageAccess::W),
            MEM_ACCESS_RW => Ok(XenPageAccess::RW),
            MEM_ACCESS_X => Ok(XenPageAccess::X),
            MEM_ACCESS_RX => Ok(XenPageAccess::RX),
            MEM_ACCESS_WX => Ok(XenPageAccess::WX),
            MEM_ACCESS_RWX => Ok(XenPageAccess::RWX),
            _ => Err("invalid access value"),
        }
    }
}

impl TryFrom<xenmem_access_t> for XenPageAccess {
    type Error = &'static str;
    fn try_from(access: xenmem_access_t) -> Result<Self, Self::Error> {
        match access {
            xenmem_access_t::XENMEM_access_n => Ok(XenPageAccess::NIL),
            xenmem_access_t::XENMEM_access_r => Ok(XenPageAccess::R),
            xenmem_access_t::XENMEM_access_w => Ok(XenPageAccess::W),
            xenmem_access_t::XENMEM_access_rw => Ok(XenPageAccess::RW),
            xenmem_access_t::XENMEM_access_x => Ok(XenPageAccess::X),
            xenmem_access_t::XENMEM_access_rx => Ok(XenPageAccess::RX),
            xenmem_access_t::XENMEM_access_wx => Ok(XenPageAccess::WX),
            xenmem_access_t::XENMEM_access_rwx => Ok(XenPageAccess::RWX),
            _ => Err("not implemented"),
        }
    }
}

impl From<XenPageAccess> for xenmem_access_t {
    fn from(access: XenPageAccess) -> Self {
        match access {
            XenPageAccess::NIL => xenmem_access_t::XENMEM_access_n,
            XenPageAccess::R => xenmem_access_t::XENMEM_access_r,
            XenPageAccess::W => xenmem_access_t::XENMEM_access_w,
            XenPageAccess::RW => xenmem_access_t::XENMEM_access_rw,
            XenPageAccess::X => xenmem_access_t::XENMEM_access_x,
            XenPageAccess::RX => xenmem_access_t::XENMEM_access_rx,
            XenPageAccess::WX => xenmem_access_t::XENMEM_access_wx,
            XenPageAccess::RWX => xenmem_access_t::XENMEM_access_rwx,
        }
    }
}

#[derive(Primitive, Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum XenCr {
    Cr0 = VM_EVENT_X86_CR0,
    Cr3 = VM_EVENT_X86_CR3,
    Cr4 = VM_EVENT_X86_CR4,
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
        value: u64,
    },
    Breakpoint {
        gpa: u64,
        insn_len: u8,
    },
    Pagefault {
        gva: u64,
        gpa: u64,
        access: XenPageAccess,
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
    ) -> Result<Self, XcError> {
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

    pub fn default() -> Result<Self, XcError> {
        Self::new(None, None, 0)
    }

    pub fn domain_hvm_getcontext_partial(
        &self,
        domid: u32,
        vcpu: u16,
    ) -> Result<hvm_hw_cpu, XcError> {
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
    ) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_hvm_setcontext)(xc, domid, buffer, size.try_into().unwrap());
        last_error!(self, ())
    }

    pub fn domain_hvm_getcontext(
        &self,
        domid: u32,
        vcpu: u16,
    ) -> Result<(*mut c_uint, hvm_hw_cpu, u32), XcError> {
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
    ) -> Result<(vm_event_sring, vm_event_back_ring, u32), XcError> {
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

    pub fn get_request(
        &self,
        back_ring: &mut vm_event_back_ring,
    ) -> Result<vm_event_request_t, XcError> {
        let mut req_cons = back_ring.req_cons;
        let req_from_ring = RING_GET_REQUEST!(back_ring, req_cons);
        req_cons += 1;
        back_ring.req_cons = req_cons;
        unsafe {
            (*(back_ring.sring)).req_event = 1 + req_cons;
        }
        last_error!(self, req_from_ring)
    }

    pub fn put_response(
        &self,
        rsp: &mut vm_event_response_t,
        back_ring: &mut vm_event_back_ring,
    ) -> Result<(), XcError> {
        let mut rsp_prod = back_ring.rsp_prod_pvt;
        let rsp_dereferenced = *rsp;
        RING_PUT_RESPONSE!(back_ring, rsp_prod, rsp_dereferenced);
        rsp_prod += 1;
        back_ring.rsp_prod_pvt = rsp_prod;
        RING_PUSH_RESPONSES!(back_ring);
        last_error!(self, ())
    }

    pub fn get_event_type(&self, req: vm_event_request_t) -> Result<XenEventType, XcError> {
        let ev_type: XenEventType;
        unsafe {
            ev_type = match req.reason {
                VM_EVENT_REASON_WRITE_CTRLREG => XenEventType::Cr {
                    cr_type: XenCr::from_i32(req.u.write_ctrlreg.index.try_into().unwrap())
                        .unwrap(),
                    new: req.u.write_ctrlreg.new_value,
                    old: req.u.write_ctrlreg.old_value,
                },
                VM_EVENT_REASON_MOV_TO_MSR => XenEventType::Msr {
                    msr_type: req.u.mov_to_msr.msr.try_into().unwrap(),
                    value: req.u.mov_to_msr.value,
                },
                VM_EVENT_REASON_SOFTWARE_BREAKPOINT => XenEventType::Breakpoint {
                    gpa: req.u.software_breakpoint.gfn << PAGE_SHIFT,
                    insn_len: req.u.software_breakpoint.insn_length.try_into().unwrap(),
                },
                VM_EVENT_REASON_MEM_ACCESS => XenEventType::Pagefault {
                    gva: req.u.mem_access.gla,
                    gpa: req.u.mem_access.gfn << PAGE_SHIFT,
                    access: {
                        let mut flag = req.u.mem_access.flags;
                        if flag >= 32 {
                            flag -= 32;
                        }
                        if flag >= 16 {
                            flag -= 16;
                        }
                        if flag >= 8 {
                            flag -= 8;
                        }
                        flag.try_into().unwrap()
                    },
                },
                _ => unimplemented!(),
            };
        }
        last_error!(self, ev_type)
    }

    pub fn monitor_disable(&self, domid: u32) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.monitor_disable)(xc, domid.try_into().unwrap());
        last_error!(self, ())
    }

    pub fn domain_pause(&self, domid: u32) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_pause)(xc, domid);
        last_error!(self, ())
    }

    pub fn domain_unpause(&self, domid: u32) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.domain_unpause)(xc, domid);
        last_error!(self, ())
    }

    pub fn monitor_software_breakpoint(&self, domid: u32, enable: bool) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_software_breakpoint)(xc, domid, enable);
        if rc < 0 {
            println!("last OS error: {:?}", Error::last_os_error());
        }
        last_error!(self, ())
    }

    pub fn monitor_mov_to_msr(&self, domid: u32, msr: u32, enable: bool) -> Result<(), XcError> {
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
    ) -> Result<(), XcError> {
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
        access: XenPageAccess,
        first_pfn: u64,
    ) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.set_mem_access)(
            xc,
            domid.try_into().unwrap(),
            access.into(),
            first_pfn,
            1,
        );
        last_error!(self, ())
    }

    pub fn get_mem_access(&self, domid: u32, pfn: u64) -> Result<XenPageAccess, XcError> {
        let xc = self.handle.as_ptr();
        let mut access: xenmem_access_t = xenmem_access_t::XENMEM_access_n;
        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.get_mem_access)(xc, domid.try_into().unwrap(), pfn, &mut access);
        last_error!(self, access.try_into().unwrap())
    }

    pub fn domain_maximum_gpfn(&self, domid: u32) -> Result<u64, XcError> {
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

    fn close(&mut self) -> Result<(), XcError> {
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
