extern crate libc;

use libc::{c_char, c_int, c_longlong};
use std::ffi::c_void;
use std::ffi::CStr;
use std::ffi::CString;

extern crate libvfio_user_sys;

use std::ptr;

use libvfio_user_sys::*;
/*
use libvfio_user_sys::vfu_ctx_t;
use libvfio_user_sys::vfu_dev_irq_type_VFU_DEV_INTX_IRQ;
use libvfio_user_sys::vfu_dev_type_t_VFU_DEV_TYPE_PCI;
use libvfio_user_sys::vfu_trans_t_VFU_TRANS_SOCK;
use libvfio_user_sys::vfu_create_ctx;
use libvfio_user_sys::vfu_pci_init;
use libvfio_user_sys::vfu_setup_region;
use libvfio_user_sys::iovec;
use libvfio_user_sys::vfu_attach_ctx;
use libvfio_user_sys::vfu_log_fn_t;
use libvfio_user_sys::vfu_pci_set_id;
use libvfio_user_sys::vfu_pci_type_t_VFU_PCI_TYPE_CONVENTIONAL;
use libvfio_user_sys::vfu_realize_ctx;
use libvfio_user_sys::vfu_run_ctx;
use libvfio_user_sys::vfu_setup_log;
use libvfio_user_sys::VFU_PCI_DEV_BAR2_REGION_IDX;
use libvfio_user_sys::VFU_REGION_FLAG_RW;
*/

unsafe extern "C" fn _log(
    vfu_ctx: *mut vfu_ctx_t,
    level: c_int,
    msg: *const ::std::os::raw::c_char,
) {
    println!("{}", CStr::from_ptr(msg).to_string_lossy().into_owned());
}

unsafe extern "C" fn bar2(
    vfu_ctx: *mut vfu_ctx_t,
    buf: *mut c_char,
    count: usize,
    offset: c_longlong,
    is_write: bool,
) -> isize {
    static mut PIN: i8 = 0;

    if offset == 0 && !is_write {
        let ptr = buf.offset(0);
        *ptr = PIN / 3;
        PIN += 1;
    }

    return count as isize;
}

fn main() {
    let sock_path = CString::new("/var/run/vfio-user.sock").unwrap();
    let p: *mut c_void = ptr::null_mut();
    let null_iovec: *mut libvfio_user_sys::iovec = std::ptr::null_mut();
    unsafe {
        let vfu_ctx = vfu_create_ctx(
            vfu_trans_t_VFU_TRANS_SOCK,
            sock_path.as_ptr(),
            0,
            p,
            vfu_dev_type_t_VFU_DEV_TYPE_PCI,
        );
        // FIXME check vfu_ctx non-null
        let mut ret;
        ret = libvfio_user_sys::vfu_setup_log(vfu_ctx, _log, LOG_DEBUG as i32);
        ret = vfu_pci_init(
            vfu_ctx,
            libvfio_user_sys::vfu_pci_type_t_VFU_PCI_TYPE_CONVENTIONAL,
            0, // FIXME PCI_HEADER_TYPE_NORMAL
            0,
        );
        assert!(ret == 0);
        libvfio_user_sys::vfu_pci_set_id(vfu_ctx, 0x494f, 0x0dc8, 0x0, 0x0);
        ret = vfu_setup_region(
            vfu_ctx, 2, // VFU_PCI_DEV_BAR2_REGION_IDX,
            0x100, bar2, 3, // VFU_REGION_FLAG_RW
            null_iovec, 0, -1, 0,
        );
        assert!(ret == 0);
        ret = libvfio_user_sys::vfu_setup_device_nr_irqs(
            vfu_ctx,
            vfu_dev_irq_type_VFU_DEV_INTX_IRQ,
            1,
        );
        assert!(ret == 0);
        ret = libvfio_user_sys::vfu_realize_ctx(vfu_ctx);
        assert!(ret == 0);
        ret = libvfio_user_sys::vfu_attach_ctx(vfu_ctx);
        assert!(ret == 0);
        ret = libvfio_user_sys::vfu_run_ctx(vfu_ctx);
        assert!(ret == 0);
    }
}
