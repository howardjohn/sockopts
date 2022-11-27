#![no_std]
#![no_main]

use aya_bpf::{
    macros::cgroup_sockopt,
    programs::SockoptContext,
};
use aya_log_ebpf::info;

#[cgroup_sockopt(getsockopt,name="sockopts")]
pub fn get_sockopts(ctx: SockoptContext) -> i32 {

    match try_sockopts(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_sockopts(ctx: SockoptContext) -> Result<i32, i32> {
    info!(&ctx, "getsockopt called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
