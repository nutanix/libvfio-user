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

        ret = vfu_pci_init(
            vfu_ctx,
            vfu_pci_type_t_VFU_PCI_TYPE_CONVENTIONAL,
            PCI_HEADER_TYPE_NORMAL as i32,
            0,
        );
        assert!(ret == 0);

        vfu_pci_set_id(vfu_ctx, 0x494f, 0x0dc8, 0x0, 0x0);
        ret = vfu_setup_region(
            vfu_ctx, 2, // VFU_PCI_DEV_BAR2_REGION_IDX,
            0x100, bar2, 3, // VFU_REGION_FLAG_RW
            ptr::null_mut(), 0, -1, 0,
        );
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
