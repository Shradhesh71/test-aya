

use aya_ebpf::{
    helpers::{ bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes, generated::bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
// use aya_ebpf_bindings::helpers::bpf_ktime_get_ns;

use crate::common::*;

const FILENAME_OFFSET: usize = 16;

#[tracepoint]
pub fn tracepoint_binary(ctx: TracePointContext) -> u32 {
    match try_tracepoint_binary(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_tracepoint_binary(ctx: TracePointContext) -> Result<u32, i64> {
    let t = unsafe{ bpf_ktime_get_ns() };
    aya_log_ebpf::debug!(&ctx, "main {}", t);
    // aya_log_ebpf::debug!(&ctx, "hook");
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    // T_ENTER.insert(&tgid, &t, 0)?;

    // // let buf = BUF.get_ptr_mut(0).ok_or(0)?;
    // BUF.insert(&tgid, &ZEROED_ARRAY, 0)?; // for reset
    // let buf = BUF.get_ptr_mut(&tgid).ok_or(0)?;

    PROGRAM.insert(&tgid, &INIT_STATE, 0)?; //CHANGED
    let program_state = unsafe { &mut *PROGRAM.get_ptr_mut(&tgid).ok_or(0)? }; //CHANGED
    program_state.t_enter = t; 

    unsafe {
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        bpf_probe_read_user_str_bytes(filename_src_addr, &mut program_state.buffer)?;
    }
    // try_tail_call(&ctx,0);


    Ok(0)
}