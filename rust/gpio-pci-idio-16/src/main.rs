/*
 * Copyright (c) 2021 Nutanix Inc. All rights reserved.
 *
 * Authors: Thanos Makatos <thanos@nutanix.com>
 *          John Levon <john.levon@nutanix.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

/*
 * FIXME
 */

extern crate libc;

use libc::{c_char, c_int, c_longlong};
use std::ffi::CStr;
use std::ffi::CString;
use std::ffi::c_void;

extern crate libvfio_user_sys;

use std::ptr;

use libvfio_user_sys::*;

unsafe extern "C" fn print_log(
    _vfu_ctx: *mut vfu_ctx_t,
    _level: c_int,
    msg: *const ::std::os::raw::c_char,
) {
    println!("{}", CStr::from_ptr(msg).to_string_lossy());
}

static mut DIRTY: bool = false;
static mut PIN: i8 = 0;

unsafe extern "C" fn bar2(
    _vfu_ctx: *mut vfu_ctx_t,
    buf: *mut c_char,
    count: usize,
    offset: c_longlong,
    is_write: bool,
) -> isize {

    if offset == 0 && !is_write {
        let ptr = buf.offset(0);
        *ptr = PIN / 3;
        PIN += 1;
    }

    return count as isize;
}

unsafe extern "C" fn migr_region_cb(
    _vfu_ctx: *mut vfu_ctx_t,
    _buf: *mut c_char,
    _count: usize,
    _offset: c_longlong,
    _is_write: bool,
) -> isize {
    assert!(false);
    return 0;
}

unsafe extern "C" fn migration_device_state_transition(
    _vfu_ctx: *mut vfu_ctx_t,
    _state: vfu_migr_state_t
) -> i32 {

    // FIXME print using print_log
    //vfu_log(vfu_ctx, LOG_DEBUG, "migration: transition to state %d", state);
    return 0;
}

unsafe extern "C" fn migration_get_pending_bytes(
    _vfu_ctx: *mut vfu_ctx_t
) -> u64 {
    if DIRTY {
        return std::mem::size_of::<i8>() as u64; // FIXME must be size_of<PIN>
    }
    return 0;
}

unsafe extern "C" fn migration_prepare_data(
    _vfu_ctx: *mut vfu_ctx_t,
    offset: *mut u64,
    size: *mut u64
) -> i32
{
    *offset = 0;
    if size != ptr::null_mut() { // null means resuming
        *size = std::mem::size_of::<i8>() as u64; // FIXME must be size_of<PIN>
    }
    return 0;
}

unsafe extern "C" fn migration_read_data(
    _vfu_ctx: *mut vfu_ctx_t,
    buf: *mut c_void,
    size: u64,
    offset: u64
) -> isize
{
    assert!(offset == 0);
    assert!(size >= std::mem::size_of::<i8>() as u64); // FIXME must be size_of<PIN>
    let ptr = buf.offset(0) as *mut i8;
    *ptr = PIN;
    DIRTY = false;
    return 0;
}

unsafe extern "C" fn migration_data_written(
    _vfu_ctx: *mut vfu_ctx_t,
    count: u64
) -> i32
{
    assert!(count == std::mem::size_of::<i8>() as u64); // FIXME must be size_of<PIN>
    return 0;
}

unsafe extern "C" fn migration_write_data(
    _vfu_ctx: *mut vfu_ctx_t,
    buf: *mut c_void,
    size: u64,
    offset: u64
) -> isize
{
    assert!(offset == 0);
    assert!(size >= std::mem::size_of::<i8>() as u64); // FIXME must be size_of<PIN>
    let ptr = buf.offset(0) as *mut i8;
    PIN = *ptr;
    return 0;
}


fn main() {
    let sock_path = CString::new("/var/run/vfio-user.sock").unwrap();

    unsafe {
        let vfu_ctx = vfu_create_ctx(
            vfu_trans_t_VFU_TRANS_SOCK,
            sock_path.as_ptr(),
            0,
            ptr::null_mut(),
            vfu_dev_type_t_VFU_DEV_TYPE_PCI,
        );

        assert!(!vfu_ctx.is_null());

        let mut ret;

        ret = vfu_setup_log(vfu_ctx, print_log, LOG_DEBUG as i32);
        assert!(ret == 0);

        ret = vfu_pci_init(
            vfu_ctx,
            vfu_pci_type_t_VFU_PCI_TYPE_CONVENTIONAL,
            PCI_HEADER_TYPE_NORMAL as i32,
            0,
        );
        assert!(ret == 0);

        vfu_pci_set_id(vfu_ctx, 0x494f, 0x0dc8, 0x0, 0x0);
        ret = vfu_setup_region(
            vfu_ctx, VFU_PCI_DEV_BAR2_REGION_IDX as i32,
            0x100, bar2, VFU_REGION_FLAG_RW as i32,
            ptr::null_mut(), 0, -1, 0,
        );
        assert!(ret == 0);

        let migr_regs_size = vfu_get_migr_register_area_size();
        let migr_data_size = sysconf(libc::_SC_PAGE_SIZE);
        let migr_size = migr_regs_size + migr_data_size as usize;

        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_MIGR_REGION_IDX as i32,
                               migr_size, migr_region_cb, // FIXME replace migr_region_cb with NULL pointer
                               VFU_REGION_FLAG_RW as i32,
                               ptr::null_mut(), 0, -1, 0);
        assert!(ret == 0);

        let migr_callbacks: vfu_migration_callbacks_t = vfu_migration_callbacks_t {
            version: VFU_MIGR_CALLBACKS_VERS as i32,
            transition: migration_device_state_transition,
            get_pending_bytes: migration_get_pending_bytes,
            prepare_data: migration_prepare_data,
            read_data: migration_read_data,
            data_written: migration_data_written,
            write_data: migration_write_data };

        ret = vfu_setup_device_migration_callbacks(vfu_ctx, &migr_callbacks,
                                                   migr_regs_size as u64);
        assert!(ret == 0);

        ret = vfu_setup_device_nr_irqs(
            vfu_ctx,
            vfu_dev_irq_type_VFU_DEV_INTX_IRQ,
            1,
        );
        assert!(ret == 0);
        ret = vfu_realize_ctx(vfu_ctx);
        assert!(ret == 0);
        ret = vfu_attach_ctx(vfu_ctx);
        assert!(ret == 0);
        ret = vfu_run_ctx(vfu_ctx);
        assert!(ret == 0);
    }
}
