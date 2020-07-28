use std::os::raw::{c_char, c_int, c_uint, c_void};

use xenctrl_sys::{domid_t, xc_error, xc_interface, xen_pfn_t, xenmem_access_t, xentoollog_logger};

use libloading::{os::unix::Symbol as RawSymbol, Library, Symbol};
use log::info;

const LIBXENCTRL_FILENAME: &str = "libxenctrl.so";
// xc_interface_open
type FnInterfaceOpen = fn(
    logger: *mut xentoollog_logger,
    dombuild_logger: *mut xentoollog_logger,
    open_flags: c_uint,
) -> *mut xc_interface;
// xc_clear_last_error
type FnClearLastError = fn(xch: *mut xc_interface);
// xc_get_last_error
type FnGetLastError = fn(handle: *mut xc_interface) -> *const xc_error;
// xc_error_code_to_desc
type FnErrorCodeToDesc = fn(code: c_int) -> *const c_char;
// xc_domain_hvm_getcontext_partial
type FnDomainHVMGetcontextPartial = fn(
    xch: *mut xc_interface,
    domid: u32,
    typecode: u16,
    instance: u16,
    ctxt_buf: *mut c_void,
    size: u32,
) -> c_int;
//xc_domain_hvm_getcontext
type FnDomainHVMGetcontext =
    fn(xch: *mut xc_interface, domid: u32, ctxt_buf: *mut c_uint, size: u32) -> c_int;
//xc_domain_setcontext
type FnDomainHVMSetcontext =
    fn(xch: *mut xc_interface, domid: u32, hvm_ctxt: *mut c_uint, size: u32) -> c_int;
// xc_monitor_enable
type FnMonitorEnable =
    fn(xch: *mut xc_interface, domain_id: domid_t, port: *mut u32) -> *mut c_void;
// xc_monitor_disable
type FnMonitorDisable = fn(xch: *mut xc_interface, domain_id: domid_t) -> c_int;
// xc_domain_pause
type FnDomainPause = fn(xch: *mut xc_interface, domid: u32) -> c_int;
// xc_domain_unpause
type FnDomainUnpause = fn(xch: *mut xc_interface, domid: u32) -> c_int;
// xc_domain_maximum_gpfn
type FnDomainMaximumGPFN =
    fn(xch: *mut xc_interface, domid: domid_t, gpfns: *mut xen_pfn_t) -> c_int;
// xc_interface_close
type FnInterfaceClose = fn(xch: *mut xc_interface) -> c_int;
//xc_monitor_software_breakpoint
type FnMonitorSoftwareBreakpoint = fn(xch: *mut xc_interface, domid: u32, enable: bool) -> c_int;
//xc_monitor_mov_to_msr
type FnMonitorMovToMsr =
    fn(xch: *mut xc_interface, domain_id: domid_t, msr: u32, enable: bool) -> c_int;
//xc_monitor_write_ctrlreg
type FnMonitorWriteCtrlreg = fn(
    xch: *mut xc_interface,
    domain_id: domid_t,
    index: u16,
    enable: bool,
    sync: bool,
    onchangeonly: bool,
) -> c_int;
//xc_get_mem_access
type FnGetMemAccess =
    fn(xch: *mut xc_interface, domain_id: domid_t, pfn: u64, access: *mut xenmem_access_t) -> c_int;
//xc_set_mem_access
type FnSetMemAccess = fn(
    xch: *mut xc_interface,
    domain_id: domid_t,
    access: xenmem_access_t,
    first_pfn: u64,
    nr: u32,
) -> c_int;

#[derive(Debug)]
pub struct LibXenCtrl {
    lib: Library,
    pub interface_open: RawSymbol<FnInterfaceOpen>,
    pub clear_last_error: RawSymbol<FnClearLastError>,
    pub get_last_error: RawSymbol<FnGetLastError>,
    pub error_code_to_desc: RawSymbol<FnErrorCodeToDesc>,
    pub domain_hvm_getcontext_partial: RawSymbol<FnDomainHVMGetcontextPartial>,
    pub domain_hvm_getcontext: RawSymbol<FnDomainHVMGetcontext>,
    pub domain_hvm_setcontext: RawSymbol<FnDomainHVMSetcontext>,
    pub monitor_enable: RawSymbol<FnMonitorEnable>,
    pub monitor_disable: RawSymbol<FnMonitorDisable>,
    pub domain_pause: RawSymbol<FnDomainPause>,
    pub domain_unpause: RawSymbol<FnDomainUnpause>,
    pub domain_maximum_gpfn: RawSymbol<FnDomainMaximumGPFN>,
    pub interface_close: RawSymbol<FnInterfaceClose>,
    pub monitor_software_breakpoint: RawSymbol<FnMonitorSoftwareBreakpoint>,
    pub monitor_mov_to_msr: RawSymbol<FnMonitorMovToMsr>,
    pub monitor_write_ctrlreg: RawSymbol<FnMonitorWriteCtrlreg>,
    pub get_mem_access: RawSymbol<FnGetMemAccess>,
    pub set_mem_access: RawSymbol<FnSetMemAccess>,
}

impl LibXenCtrl {
    pub unsafe fn new() -> Self {
        info!("Loading {}", LIBXENCTRL_FILENAME);
        let lib = Library::new(LIBXENCTRL_FILENAME).unwrap();
        // load symbols
        let interface_open_sym: Symbol<FnInterfaceOpen> = lib.get(b"xc_interface_open\0").unwrap();
        let interface_open = interface_open_sym.into_raw();

        let clear_last_error_sym: Symbol<FnClearLastError> =
            lib.get(b"xc_clear_last_error\0").unwrap();
        let clear_last_error = clear_last_error_sym.into_raw();

        let get_last_error_sym: Symbol<FnGetLastError> = lib.get(b"xc_get_last_error\0").unwrap();
        let get_last_error = get_last_error_sym.into_raw();

        let error_code_to_desc_sym: Symbol<FnErrorCodeToDesc> =
            lib.get(b"xc_error_code_to_desc\0").unwrap();
        let error_code_to_desc = error_code_to_desc_sym.into_raw();

        let domain_hvm_getcontext_partial_sym: Symbol<FnDomainHVMGetcontextPartial> =
            lib.get(b"xc_domain_hvm_getcontext_partial\0").unwrap();
        let domain_hvm_getcontext_partial = domain_hvm_getcontext_partial_sym.into_raw();

        let domain_hvm_getcontext_sym: Symbol<FnDomainHVMGetcontext> =
            lib.get(b"xc_domain_hvm_getcontext\0").unwrap();
        let domain_hvm_getcontext = domain_hvm_getcontext_sym.into_raw();

        let domain_hvm_setcontext_sym: Symbol<FnDomainHVMSetcontext> =
            lib.get(b"xc_domain_hvm_setcontext\0").unwrap();
        let domain_hvm_setcontext = domain_hvm_setcontext_sym.into_raw();

        let monitor_enable_sym: Symbol<FnMonitorEnable> = lib.get(b"xc_monitor_enable\0").unwrap();
        let monitor_enable = monitor_enable_sym.into_raw();

        let monitor_disable_sym: Symbol<FnMonitorDisable> =
            lib.get(b"xc_monitor_disable\0").unwrap();
        let monitor_disable = monitor_disable_sym.into_raw();

        let domain_pause_sym: Symbol<FnDomainPause> = lib.get(b"xc_domain_pause\0").unwrap();
        let domain_pause = domain_pause_sym.into_raw();

        let monitor_software_breakpoint_sym: Symbol<FnMonitorSoftwareBreakpoint> =
            lib.get(b"xc_monitor_software_breakpoint\0").unwrap();
        let monitor_software_breakpoint = monitor_software_breakpoint_sym.into_raw();

        let monitor_mov_to_msr_sym: Symbol<FnMonitorMovToMsr> =
            lib.get(b"xc_monitor_mov_to_msr\0").unwrap();
        let monitor_mov_to_msr = monitor_mov_to_msr_sym.into_raw();

        let monitor_write_ctrlreg_sym: Symbol<FnMonitorWriteCtrlreg> =
            lib.get(b"xc_monitor_write_ctrlreg\0").unwrap();
        let monitor_write_ctrlreg = monitor_write_ctrlreg_sym.into_raw();

        let get_mem_access_sym: Symbol<FnGetMemAccess> = lib.get(b"xc_get_mem_access\0").unwrap();
        let get_mem_access = get_mem_access_sym.into_raw();

        let set_mem_access_sym: Symbol<FnSetMemAccess> = lib.get(b"xc_set_mem_access\0").unwrap();
        let set_mem_access = set_mem_access_sym.into_raw();

        let domain_unpause_sym: Symbol<FnDomainUnpause> = lib.get(b"xc_domain_unpause\0").unwrap();
        let domain_unpause = domain_unpause_sym.into_raw();

        let domain_maximum_gpfn_sym: Symbol<FnDomainMaximumGPFN> =
            lib.get(b"xc_domain_maximum_gpfn\0").unwrap();
        let domain_maximum_gpfn = domain_maximum_gpfn_sym.into_raw();

        let interface_close_sym: Symbol<FnInterfaceClose> =
            lib.get(b"xc_interface_close\0").unwrap();
        let interface_close = interface_close_sym.into_raw();

        LibXenCtrl {
            lib,
            interface_open,
            clear_last_error,
            get_last_error,
            error_code_to_desc,
            domain_hvm_getcontext_partial,
            domain_hvm_getcontext,
            domain_hvm_setcontext,
            monitor_enable,
            monitor_disable,
            monitor_software_breakpoint,
            monitor_mov_to_msr,
            monitor_write_ctrlreg,
            get_mem_access,
            set_mem_access,
            domain_pause,
            domain_unpause,
            domain_maximum_gpfn,
            interface_close,
        }
    }
}
