pub mod consts;
pub mod error;
mod libxenctrl;

#[macro_use]
mod macros;
#[macro_use]
extern crate log;

extern crate xenctrl_sys;

use self::consts::PAGE_SIZE;
use enum_primitive_derive::Primitive;
use libxenctrl::LibXenCtrl;
use num_traits::FromPrimitive;
use std::{
    alloc::{alloc_zeroed, Layout},
    convert::{From, TryFrom, TryInto},
    ffi::{self, c_void},
    io::Error,
    mem,
    os::raw::{c_int, c_uint},
    ptr::{null_mut, NonNull},
    slice,
};

use xenctrl_sys::{
    xc_cx_stat, xc_error_code_XC_ERROR_NONE, xc_error_code_XC_INTERNAL_ERROR, xc_interface,
    xc_px_stat, xc_px_val, xenmem_access_t, xenmem_access_t_XENMEM_access_n,
    xenmem_access_t_XENMEM_access_r, xenmem_access_t_XENMEM_access_rw,
    xenmem_access_t_XENMEM_access_rwx, xenmem_access_t_XENMEM_access_rx,
    xenmem_access_t_XENMEM_access_w, xenmem_access_t_XENMEM_access_wx,
    xenmem_access_t_XENMEM_access_x, xentoollog_logger,
};
use xenvmevent_sys::{
    vm_event_back_ring, vm_event_request_t, vm_event_response_t, vm_event_sring,
    VM_EVENT_REASON_MEM_ACCESS, VM_EVENT_REASON_MOV_TO_MSR, VM_EVENT_REASON_SINGLESTEP,
    VM_EVENT_REASON_SOFTWARE_BREAKPOINT, VM_EVENT_REASON_WRITE_CTRLREG, VM_EVENT_X86_CR0,
    VM_EVENT_X86_CR3, VM_EVENT_X86_CR4,
};

// re-exported definitions
pub use xenctrl_sys::{
    hvm_hw_cpu, hvm_save_descriptor, xc_cpuinfo_t, xc_dominfo_t, xc_physinfo_t, xc_vcpuinfo_t,
    XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF, XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON, __HVM_SAVE_TYPE_CPU,
};

use error::XcError;

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

impl TryFrom<xenmem_access_t> for XenPageAccess {
    type Error = &'static str;
    fn try_from(access: xenmem_access_t) -> Result<Self, Self::Error> {
        #[allow(non_upper_case_globals)]
        match access {
            xenmem_access_t_XENMEM_access_n => Ok(XenPageAccess::NIL),
            xenmem_access_t_XENMEM_access_r => Ok(XenPageAccess::R),
            xenmem_access_t_XENMEM_access_w => Ok(XenPageAccess::W),
            xenmem_access_t_XENMEM_access_rw => Ok(XenPageAccess::RW),
            xenmem_access_t_XENMEM_access_x => Ok(XenPageAccess::X),
            xenmem_access_t_XENMEM_access_rx => Ok(XenPageAccess::RX),
            xenmem_access_t_XENMEM_access_wx => Ok(XenPageAccess::WX),
            xenmem_access_t_XENMEM_access_rwx => Ok(XenPageAccess::RWX),
            _ => Err("not implemented"),
        }
    }
}

impl From<XenPageAccess> for xenmem_access_t {
    fn from(access: XenPageAccess) -> Self {
        match access {
            XenPageAccess::NIL => xenmem_access_t_XENMEM_access_n,
            XenPageAccess::R => xenmem_access_t_XENMEM_access_r,
            XenPageAccess::W => xenmem_access_t_XENMEM_access_w,
            XenPageAccess::RW => xenmem_access_t_XENMEM_access_rw,
            XenPageAccess::X => xenmem_access_t_XENMEM_access_x,
            XenPageAccess::RX => xenmem_access_t_XENMEM_access_rx,
            XenPageAccess::WX => xenmem_access_t_XENMEM_access_wx,
            XenPageAccess::RWX => xenmem_access_t_XENMEM_access_rwx,
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
        gfn: u64,
        gpa: u64,
        insn_len: u8,
    },
    Pagefault {
        gva: u64,
        gpa: u64,
        access: xenmem_access_t,
        view: u16,
    },
    Singlestep {
        gfn: u64,
    },
}

#[derive(Debug)]
pub struct XenControl {
    handle: NonNull<xc_interface>,
    libxenctrl: LibXenCtrl,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct XcVcpuInfo {
    pub vcpu: u32,
    pub online: u8,
    pub blocked: u8,
    pub running: u8,
    pub cpu_time: u64,
    pub cpu: u32,
}

impl From<xc_vcpuinfo_t> for XcVcpuInfo {
    fn from(value: xc_vcpuinfo_t) -> Self {
        Self {
            vcpu: value.vcpu,
            online: value.online,
            blocked: value.blocked,
            running: value.running,
            cpu_time: value.cpu_time,
            cpu: value.cpu,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PxStat {
    pub total: u8,
    pub usable: u8,
    pub last: u8,
    pub cur: u8,
    pub transition_table: Vec<u64>,
    pub values: Vec<xc_px_val>,
}

#[derive(Debug, Clone, Default)]
pub struct CxStat {
    pub nr: u32,
    pub last: u32,
    pub idle_time: u64,
    pub triggers: Vec<u64>,
    pub residencies: Vec<u64>,
    pub nr_pc: u32,
    pub nr_cc: u32,
    pub pc: Vec<u64>,
    pub cc: Vec<u64>,
}

impl XenControl {
    pub fn new(
        logger: Option<&mut xentoollog_logger>,
        dombuild_logger: Option<&mut xentoollog_logger>,
        open_flags: u32,
    ) -> Result<Self, XcError> {
        let libxenctrl = unsafe { LibXenCtrl::new()? };

        #[allow(clippy::redundant_closure)]
        let xc_handle = (libxenctrl.interface_open)(
            logger.map_or_else(|| null_mut(), |l| l as *mut _),
            dombuild_logger.map_or_else(|| null_mut(), |l| l as *mut _),
            open_flags,
        );

        NonNull::new(xc_handle)
            .ok_or_else(|| {
                let desc = (libxenctrl.error_code_to_desc)(xc_error_code_XC_INTERNAL_ERROR as _);
                XcError::new(unsafe { ffi::CStr::from_ptr(desc) }.to_str().unwrap())
            })
            .map(|handle| XenControl { handle, libxenctrl })
    }

    pub fn new_default() -> Result<Self, XcError> {
        Self::new(None, None, 0)
    }

    pub fn domain_getinfo(&self, domid: u32) -> Result<Option<xc_dominfo_t>, XcError> {
        let xc = self.handle.as_ptr();
        let mut domain_info = unsafe { mem::zeroed() };
        (self.libxenctrl.clear_last_error)(xc);
        let count = (self.libxenctrl.domain_getinfo)(xc, domid, 1, &mut domain_info);
        last_error!(
            self,
            if count == 1 { Some(domain_info) } else { None },
            count
        )
    }

    pub fn domain_debug_control(&self, domid: u32, op: u32, vcpu: u32) -> Result<(), XcError> {
        debug!("domain_debug_control: op: {}, vcpu: {}", op, vcpu);
        (self.libxenctrl.clear_last_error)(self.handle.as_ptr());
        let rc = (self.libxenctrl.domain_debug_control)(self.handle.as_ptr(), domid, op, vcpu);
        last_error!(self, (), rc)
    }

    pub fn domain_hvm_getcontext_partial(
        &self,
        domid: u32,
        vcpu: u16,
    ) -> Result<hvm_hw_cpu, XcError> {
        let xc = self.handle.as_ptr();
        let mut hvm_cpu: hvm_hw_cpu = unsafe { mem::zeroed() };
        // cast to mut c_void*
        let hvm_cpu_ptr = &mut hvm_cpu as *mut _ as *mut c_void;
        let hvm_size: u32 = mem::size_of::<hvm_hw_cpu>().try_into().unwrap();
        let hvm_save_cpu: __HVM_SAVE_TYPE_CPU = unsafe { mem::zeroed() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_cpu.c).try_into().unwrap();

        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.domain_hvm_getcontext_partial)(
            xc,
            domid,
            hvm_save_code_cpu,
            vcpu,
            hvm_cpu_ptr,
            hvm_size,
        );
        last_error!(self, hvm_cpu, rc)
    }

    pub fn domain_hvm_setcontext(
        &self,
        domid: u32,
        buffer: *mut c_uint,
        size: usize,
    ) -> Result<(), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc =
            (self.libxenctrl.domain_hvm_setcontext)(xc, domid, buffer, size.try_into().unwrap());
        last_error!(self, (), rc)
    }

    pub fn domain_hvm_getcontext(
        &self,
        domid: u32,
        vcpu: u16,
    ) -> Result<(*mut c_uint, hvm_hw_cpu, u32), XcError> {
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        // calling with no arguments --> return is the size of buffer required for storing the HVM context
        let size =
            (self.libxenctrl.domain_hvm_getcontext)(xc, domid, std::ptr::null_mut::<u32>(), 0);
        let layout =
            Layout::from_size_align(size.try_into().unwrap(), mem::align_of::<u8>()).unwrap();
        #[allow(clippy::cast_ptr_alignment)]
        let buffer = unsafe { alloc_zeroed(layout) as *mut c_uint };
        (self.libxenctrl.clear_last_error)(xc);
        // Locate runtime CPU registers in the context record. This function returns information about the context of a hvm domain.
        (self.libxenctrl.domain_hvm_getcontext)(xc, domid, buffer, size.try_into().unwrap());
        let mut offset: u32 = 0;
        let hvm_save_cpu: __HVM_SAVE_TYPE_CPU = unsafe { mem::zeroed() };
        let hvm_save_code_cpu: u16 = mem::size_of_val(&hvm_save_cpu.c).try_into().unwrap();
        let mut cpu_ptr: *mut hvm_hw_cpu = std::ptr::null_mut();
        unsafe {
            // The execution context of the hvm domain is stored in the buffer struct we passed in domain_hvm_getcontext(). We iterate from the beginning address of this struct until we find the particular descriptor having typecode HVM_SAVE_CODE(CPU) which gives us the info about the registers in the particular vcpu.
            // Note that domain_hvm_getcontext_partial(), unlike domain_hvm_getcontext() returns only the descriptor struct having a particular typecode passed as one of its argument.
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
    ) -> Result<(*mut vm_event_sring, vm_event_back_ring, u32), XcError> {
        debug!("monitor_enable");
        let xc = self.handle.as_ptr();
        let mut remote_port: u32 = 0;
        (self.libxenctrl.clear_last_error)(xc);
        let void_ring_page: *mut c_void =
            (self.libxenctrl.monitor_enable)(xc, domid.try_into().unwrap(), &mut remote_port);
        if void_ring_page.is_null() {
            return Err(XcError::new(
                "Failed to enable event monitor ring: ring page is null",
            ));
        }
        let ring_page = void_ring_page as *mut vm_event_sring;
        unsafe {
            (*ring_page).req_prod = 0;
            (*ring_page).rsp_prod = 0;
            (*ring_page).req_event = 1;
            (*ring_page).rsp_event = 1;
            (*ring_page).pvt.pvt_pad = mem::zeroed();
            (*ring_page).__pad = mem::zeroed();
        }
        // BACK_RING_INIT(&back_ring, ring_page, XC_PAGE_SIZE);
        let mut back_ring: vm_event_back_ring = unsafe { mem::zeroed() };
        back_ring.rsp_prod_pvt = 0;
        back_ring.req_cons = 0;
        back_ring.nr_ents = __RING_SIZE!(ring_page, PAGE_SIZE);
        back_ring.sring = ring_page;
        Ok((ring_page, back_ring, remote_port))
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
        Ok(req_from_ring)
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
        Ok(())
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
                    value: req.u.mov_to_msr.new_value,
                },
                VM_EVENT_REASON_SOFTWARE_BREAKPOINT => XenEventType::Breakpoint {
                    gfn: req.u.software_breakpoint.gfn,
                    gpa: 0, // not available
                    insn_len: req.u.software_breakpoint.insn_length.try_into().unwrap(),
                },
                VM_EVENT_REASON_MEM_ACCESS => XenEventType::Pagefault {
                    gva: req.u.mem_access.gla,
                    gpa: 0, // not available
                    access: req.u.mem_access.flags,
                    view: 0,
                },
                VM_EVENT_REASON_SINGLESTEP => XenEventType::Singlestep {
                    gfn: req.u.singlestep.gfn,
                },
                _ => unimplemented!(),
            };
        }
        Ok(ev_type)
    }

    pub fn monitor_disable(&self, domid: u32) -> Result<(), XcError> {
        debug!("monitor_disable");
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_disable)(xc, domid.try_into().unwrap());
        last_error!(self, (), rc)
    }

    pub fn domain_pause(&self, domid: u32) -> Result<(), XcError> {
        debug!("domain pause");
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.domain_pause)(xc, domid);
        last_error!(self, (), rc)
    }

    pub fn domain_unpause(&self, domid: u32) -> Result<(), XcError> {
        debug!("domain_unpause");
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.domain_unpause)(xc, domid);
        last_error!(self, (), rc)
    }

    pub fn monitor_software_breakpoint(&self, domid: u32, enable: bool) -> Result<(), XcError> {
        debug!("monitor_software_breakpoint: {}", enable);
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_software_breakpoint)(xc, domid, enable);
        if rc < 0 {
            debug!("The error is {}", Error::last_os_error());
        }
        last_error!(self, (), rc)
    }

    pub fn monitor_mov_to_msr(&self, domid: u32, msr: u32, enable: bool) -> Result<(), XcError> {
        debug!("monitor_mov_to_msr: {:x} {}", msr, enable);
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.monitor_mov_to_msr)(xc, domid.try_into().unwrap(), msr, enable);
        if rc < 0 {
            debug!("The error is {}", Error::last_os_error());
        }
        last_error!(self, (), rc)
    }

    pub fn monitor_singlestep(&self, domid: u32, enable: bool) -> Result<(), XcError> {
        debug!("monitor_singlestep: {}", enable);
        (self.libxenctrl.clear_last_error)(self.handle.as_ptr());
        let rc = (self.libxenctrl.monitor_singlestep)(
            self.handle.as_ptr(),
            domid.try_into().unwrap(),
            enable,
        );
        last_error!(self, (), rc)
    }

    pub fn monitor_write_ctrlreg(
        &self,
        domid: u32,
        index: XenCr,
        enable: bool,
        sync: bool,
        onchangeonly: bool,
    ) -> Result<(), XcError> {
        debug!("monitor_write_ctrlreg: {:?} {}", index, enable);
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
            debug!("The error is {}", Error::last_os_error());
        }
        last_error!(self, (), rc)
    }

    pub fn set_mem_access(
        &self,
        domid: u32,
        access: XenPageAccess,
        first_pfn: u64,
        nr: u32,
    ) -> Result<(), XcError> {
        debug!("set_mem_access: {:?} on pfn {}", access, first_pfn);
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.set_mem_access)(
            xc,
            domid.try_into().unwrap(),
            access.try_into().unwrap(),
            first_pfn,
            nr,
        );
        last_error!(self, (), rc)
    }

    pub fn get_mem_access(&self, domid: u32, pfn: u64) -> Result<XenPageAccess, XcError> {
        debug!("get_mem_access");
        let xc = self.handle.as_ptr();
        let mut access: xenmem_access_t = xenmem_access_t_XENMEM_access_n;
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.get_mem_access)(xc, domid.try_into().unwrap(), pfn, &mut access);
        last_error!(self, access.try_into().unwrap(), rc)
    }

    pub fn domain_maximum_gpfn(&self, domid: u32) -> Result<u64, XcError> {
        debug!("domain_maximum_gfn");
        let xc = self.handle.as_ptr();
        #[allow(unused_assignments)]
        (self.libxenctrl.clear_last_error)(xc);
        let mut max_gpfn: u64 = 0;
        let rc =
            (self.libxenctrl.domain_maximum_gpfn)(xc, domid.try_into().unwrap(), &mut max_gpfn);
        last_error!(self, max_gpfn, rc)
    }

    pub fn vcpu_getinfo(&self, domid: u32, vcpu: u32) -> Result<XcVcpuInfo, XcError> {
        debug!("vcpu_getinfo");
        let xc = self.handle.as_ptr();
        let mut vcpu_info = unsafe { mem::zeroed() };

        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.vcpu_getinfo)(xc, domid, vcpu, &mut vcpu_info);

        last_error!(self, XcVcpuInfo::from(vcpu_info), rc)
    }

    pub fn physinfo(&self) -> Result<xc_physinfo_t, XcError> {
        debug!("physinfo");
        let xc = self.handle.as_ptr();
        let mut physinfo = unsafe { mem::zeroed() };

        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.physinfo)(xc, &mut physinfo);

        last_error!(self, physinfo, rc)
    }

    pub fn get_cpuinfo(&self, max_cpus: usize) -> Result<Vec<xc_cpuinfo_t>, XcError> {
        debug!("get_cpuinfo");
        let mut infos = vec![xc_cpuinfo_t { idletime: 0 }; max_cpus];
        let mut nr_cpus: i32 = 0;

        let rc = (self.libxenctrl.get_cpuinfo)(
            self.handle.as_ptr(),
            infos.len() as i32,
            infos.as_mut_ptr() as _,
            &mut nr_cpus,
        );

        infos.truncate(nr_cpus as usize);

        last_error!(self, infos, rc)
    }

    pub fn get_cpufreq_avg(&self, cpuid: u32) -> Result<u32, XcError> {
        debug!("get_cpufreq_avg");
        let xc = self.handle.as_ptr();
        let mut freq: c_int = 0;

        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.get_cpufreq_avgfreq)(xc, cpuid as c_int, &mut freq);

        last_error!(self, freq as _, rc)
    }

    /// As [PxStat] can hold quite large structures, you need to create an empty one using [Default] trait and
    /// provide it as `px_stat` to this function that will update the values.
    pub fn get_pxstat(&self, cpuid: u32, px_stat: &mut PxStat) -> Result<(), XcError> {
        debug!("get_pxstat");
        let xc = self.handle.as_ptr();

        let mut max_px: c_int = 0;

        (self.libxenctrl.clear_last_error)(xc);
        let ret = (self.libxenctrl.get_max_px)(xc, cpuid as _, &mut max_px);

        if ret != 0 {
            return last_error!(self, ());
        }

        px_stat.values.resize(
            max_px as _,
            xc_px_val {
                freq: 0,
                residency: 0,
                count: 0,
            },
        );

        px_stat
            .transition_table
            .resize((max_px * max_px) as usize, 0);

        let mut px_stat_ffi = xc_px_stat {
            total: 0,
            usable: 0,
            last: 0,
            cur: 0,
            trans_pt: px_stat.transition_table.as_mut_ptr(),
            pt: px_stat.values.as_mut_ptr(),
        };

        (self.libxenctrl.clear_last_error)(xc);
        let ret = (self.libxenctrl.get_pxstat)(xc, cpuid as c_int, &mut px_stat_ffi);

        if ret == 0 {
            px_stat.total = px_stat_ffi.total;
            px_stat.usable = px_stat_ffi.usable;
            px_stat.last = px_stat_ffi.last;
            px_stat.cur = px_stat_ffi.cur;
        }

        last_error!(self, (), ret)
    }

    /// As [CxStat] can hold quite large structures, you need to create an empty one using [Default] trait and
    /// provide it as `cx_stat` to this function that will update the values.
    pub fn get_cxstat(&self, cpuid: u32, cx_stat: &mut CxStat) -> Result<(), XcError> {
        debug!("get_cxstat");
        let xc = self.handle.as_ptr();
        let mut max_cx: c_int = 0;

        (self.libxenctrl.clear_last_error)(xc);
        let ret = (self.libxenctrl.get_max_cx)(xc, cpuid as _, &mut max_cx);

        if ret != 0 {
            return last_error!(self, ());
        }

        const MAX_PKG_RESIDENCIES: usize = 12;
        const MAX_CORE_RESIDENCIES: usize = 8;

        cx_stat.triggers.resize(max_cx as _, 0);
        cx_stat.residencies.resize(max_cx as _, 0);
        cx_stat.pc.resize(MAX_PKG_RESIDENCIES, 0);
        cx_stat.cc.resize(MAX_CORE_RESIDENCIES, 0);

        let mut cx_stat_ffi = xc_cx_stat {
            nr: max_cx as u32,
            last: 0,
            idle_time: 0,
            triggers: cx_stat.triggers.as_mut_ptr(),
            residencies: cx_stat.residencies.as_mut_ptr(),
            nr_pc: MAX_PKG_RESIDENCIES as u32,
            nr_cc: MAX_CORE_RESIDENCIES as u32,
            pc: cx_stat.pc.as_mut_ptr(),
            cc: cx_stat.cc.as_mut_ptr(),
        };

        (self.libxenctrl.clear_last_error)(xc);
        (self.libxenctrl.get_cxstat)(xc, cpuid as c_int, &mut cx_stat_ffi);

        if ret == 0 {
            cx_stat.nr = cx_stat_ffi.nr;
            cx_stat.last = cx_stat_ffi.last;
            cx_stat.idle_time = cx_stat_ffi.idle_time;
            cx_stat.nr_pc = cx_stat_ffi.nr_pc;
            cx_stat.nr_cc = cx_stat_ffi.nr_cc;
        }

        last_error!(self, (), ret)
    }

    fn close(&mut self) -> Result<(), XcError> {
        debug!("closing");
        let xc = self.handle.as_ptr();
        (self.libxenctrl.clear_last_error)(xc);
        let rc = (self.libxenctrl.interface_close)(xc);
        last_error!(self, (), rc)
    }
}

impl Drop for XenControl {
    fn drop(&mut self) {
        self.close().unwrap();
    }
}
