#![no_std]
#![no_main]

use aya_bpf::{bpf_printk, macros::cgroup_sockopt, programs::SockoptContext};

#[cgroup_sockopt(getsockopt, name = "get_sockopts")]
pub fn get_sockopts(ctx: SockoptContext) -> i32 {
    match try_sockopts(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[cgroup_sockopt(setsockopt, name = "set_sockopts")]
pub fn set_sockopts(ctx: SockoptContext) -> i32 {
    match try_set_sockopts(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[allow(overflowing_literals)]
const SOL_CUSTOM: i32 = 0xdeadbeef;

fn try_sockopts(ctx: SockoptContext) -> Result<i32, i32> {
    let mut s = unsafe { *ctx.sockopt };
    if s.level != SOL_CUSTOM {
        // Not our custom one, send it back
        return Ok(1);
    }
    unsafe {
        bpf_printk!(b"get SOL_CUSTOM", (*ctx.sockopt).level);
    }
    unsafe {
        if (*ctx.sockopt).__bindgen_anon_2.optval as usize + 128 > (*ctx.sockopt).__bindgen_anon_3.optval_end as usize {
            return Ok(0);
        }
    }
    // Override kernel error
    unsafe { (*ctx.sockopt).retval = 0 };
    unsafe {
        let data: &mut [u8; 1] = &mut [101; 1];
        if (*ctx.sockopt).__bindgen_anon_2.optval as usize + 128 > (*ctx.sockopt).__bindgen_anon_3.optval_end as usize {
            return Ok(0);
        }
        // let mut val = 1;
        // let d = &val as *mut c_void;
        // *((*ctx.sockopt).__bindgen_anon_2.optval) = *d;
        // core::ptr::copy_nonoverlapping(data.as_ptr(), ((*ctx.sockopt).__bindgen_anon_2.optval) as *mut u8, 6);
        // if (*ctx.sockopt).optlen > 3 {
        //     (*ctx.sockopt).optlen = 3;
        // }
        let mut ov = (*ctx.sockopt).__bindgen_anon_2.optval;
        for v in b"hello" {
            ov.write_bytes(*v, 1);
            ov = ov.offset(1)
        }
        let mut ol = (*ctx.sockopt).optlen;
        ol = 1;
        // ((*ctx.sockopt).__bindgen_anon_2.optval) = data.as_ptr() as *mut c_void;
        bpf_printk!(b"get sock name %d", (*ctx.sockopt).optname);
        bpf_printk!(b"get sock len %d", (*ctx.sockopt).optlen);
        bpf_printk!(b"get sock retval %d", (*ctx.sockopt).retval);
    }
    return Ok(1);
}

fn try_set_sockopts(ctx: SockoptContext) -> Result<i32, i32> {
    let mut s = unsafe { *ctx.sockopt };
    if s.level != SOL_CUSTOM {
        // Not our custom one, send it back
        return Ok(1);
    }

    unsafe {
        bpf_printk!(b"set SOL_CUSTOM %d", (*ctx.sockopt).level);
    }
    unsafe {
        if (*ctx.sockopt).__bindgen_anon_2.optval as usize + 16 > (*ctx.sockopt).__bindgen_anon_3.optval_end as usize {
            return Ok(0);
        }
    }
    unsafe {
        bpf_printk!(b"set SOL_CUSTOM %d", (*ctx.sockopt).level);


        bpf_printk!(b"set sock name %d", (*ctx.sockopt).optname);
        bpf_printk!(b"set sock len %d", (*ctx.sockopt).optlen);
        // bpf_printk!(b"set sock retval %d", (*ctx.sockopt).retval);
        bpf_printk!(b"set sock optval: %s", (*ctx.sockopt).__bindgen_anon_2.optval);
    }
    // Override kernel error
    // unsafe { (*ctx.sockopt).retval = 0 };
    // We consumed this value
    unsafe {
        (*ctx.sockopt).optlen = -1;
    }
    Ok(1)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
