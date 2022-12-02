#![no_std]
#![no_main]

use aya_bpf::{
    macros::map,
    maps::HashMap,
};
use aya_bpf::{bpf_printk, macros::cgroup_sockopt, programs::SockoptContext};


#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnectionTuple {
    pub daddr: u32,
    pub dport: u32,
    pub saddr: u32,
    pub sport: u32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct Metadata {
    pub identity: [u8; 256]
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendKey {}


#[map(name = "HOWARDJOHN_MAP")]
static mut HOWARDJOHN_MAP: HashMap<ConnectionTuple, Metadata> = HashMap::<ConnectionTuple, Metadata>::with_max_entries(128, 0);
#[map(name = "HOWARDJOHN_MAP2")]
static mut HOWARDJOHN_MAP2: HashMap<ConnectionTuple, u16> = HashMap::<ConnectionTuple, u16>::with_max_entries(128, 0);

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
        let sk = *((*ctx.sockopt).__bindgen_anon_1.sk);
        bpf_printk!(b"get dip %d", u32::from_be(sk.dst_ip4));
        bpf_printk!(b"get dport %d", u16::from_be(sk.dst_port));
        let ct = ConnectionTuple{
            daddr: sk.dst_ip4,
            dport:  u16::from_be(sk.dst_port) as u32,
            saddr: sk.dst_ip4,
            sport: u16::from_be(sk.dst_port) as u32,
        };
        let id = if let Some(m) = HOWARDJOHN_MAP.get(&ct) {
            bpf_printk!(b"get identity %d", m.identity[0]);
            m.identity
        } else {
            bpf_printk!(b"failed identity");
            return Ok(0)
        };
        if (*ctx.sockopt).__bindgen_anon_2.optval as usize + 256 > (*ctx.sockopt).__bindgen_anon_3.optval_end as usize {

            bpf_printk!(b"small opt %d", (*ctx.sockopt).__bindgen_anon_3.optval_end as usize - (*ctx.sockopt).__bindgen_anon_2.optval as usize);
            return Ok(0);
        }
        let mut ov = (*ctx.sockopt).__bindgen_anon_2.optval;
        for v in id {
            ov.write_bytes(v, 1);
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
        let sk = *((*ctx.sockopt).__bindgen_anon_1.sk);
        let ct = ConnectionTuple{
            daddr: sk.dst_ip4,
            dport:  u16::from_be(sk.dst_port) as u32,
            saddr: sk.dst_ip4,
            sport: u16::from_be(sk.dst_port) as u32,
        };
        let mut id: [u8; 256] = [0; 256];
        for (i, b) in b"from ebpf".iter().enumerate() {
            id[i] = *b;
        }
        // if let Err(e) = id.writer().write_all(b"from bpf") {
        //     return Ok(0);
        // }
        let meta = Metadata{
            identity: id,
        };
        if let Err(e) = HOWARDJOHN_MAP.insert(&ct, &meta, 0u64) {
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
