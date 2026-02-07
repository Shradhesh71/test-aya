#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn test_aya(ctx: TracePointContext) -> u32 {
    match try_test_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_test_aya(ctx: TracePointContext) -> Result<u32, i64> {
    // let filename = unsafe {ctx.read_at::<u64>(16)?};

    let filename_src_addr = unsafe {ctx.read_at::<*const u8>(16)?};
    let mut buf = [0u8; 16];
    let _filename_bytes: &[u8] = unsafe {
        aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_src_addr, &mut buf)?
    };
    let _filename = unsafe {
        core::str::from_utf8_unchecked(_filename_bytes)
    };
    // info!(&ctx, "tracepoint sys_enter_execve called {}",filename_src_addr as u64); // byte-coded file name
    info!(&ctx, "tracepoint sys_enter_execve called {}",_filename);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
