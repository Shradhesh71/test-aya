// use core::str::from_utf8_unchecked;

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_ktime_get_ns}, macros::tracepoint, programs::TracePointContext
};
use aya_log_ebpf::info;

use crate::common::{PROGRAM, try_tail_call};

// use crate::common::{BUF, T_ENTER};

// use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

#[tracepoint]
pub fn tracepoint_binary_exit(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary_exit(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let t =  unsafe {
        bpf_ktime_get_ns()
    };
    aya_log_ebpf::debug!(&ctx, "exit {}",t);
    let tgid = (bpf_get_current_pid_tgid() >> 32 ) as u32;
    // let t_enter = unsafe {
    //     T_ENTER.get(&tgid).ok_or(0)?
    // };

    // let buf = unsafe { BUF.get(&tgid).ok_or(0)? }; 
    // let cmd = &buf[..]; 
    // let filename = unsafe { from_utf8_unchecked(cmd) };
    
    let ret = unsafe {
        ctx.read_at::<i64>(16)?
    };

    let program_state = unsafe {
        &mut *PROGRAM.get_ptr_mut(&tgid).ok_or(0)?
    };
    program_state.t_exit=t;
    program_state.ret=ret;
    try_tail_call(&ctx,0);
    info!(&ctx, "tracepoint sys_exit_execve called. ret:{}",ret);
    Ok(0)
}