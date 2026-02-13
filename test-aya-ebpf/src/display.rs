use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext
};

use aya_log_ebpf::{debug, info};
use core::str::from_utf8_unchecked;
use crate::common::*;

#[tracepoint]
pub fn test_aya_display(ctx: TracePointContext) -> u32 {
    match try_test_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}
fn try_test_aya(ctx: TracePointContext) -> Result<u32, i64> {
    debug!(&ctx, "display");
    // let buf = BUF.get(0).ok_or(0)?;
    let tgid = (bpf_get_current_pid_tgid() >> 32)as u32;
    // let buf = unsafe {
    //     BUF.get(&tgid).ok_or(0)?
    // };

    let program = unsafe {
        PROGRAM.get(&tgid).ok_or(0)?
    };
    let cmd = &program.buffer[..];
    let filename = unsafe { from_utf8_unchecked(cmd) };
    let duration= program.t_exit-program.t_enter;
    info!(&ctx, "tracepoint sys_enter_execve called. Binary: {}, Duration: {}ns", filename, duration);
    
    Ok(0)
}
