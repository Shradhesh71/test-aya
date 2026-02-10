#![no_std]
#![no_main]

use aya_ebpf::{macros::{map, tracepoint}, maps::{HashMap, PerCpuArray}, programs::TracePointContext};
use aya_log_ebpf::info;

const LEN_MAX_PATH: usize = 512; 
const FILENAME_OFFSET: usize = 16;

#[map]
static BUF: PerCpuArray<[u8; LEN_MAX_PATH]> = PerCpuArray::with_max_entries(1, 0);

#[map]
static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);


#[tracepoint]
pub fn test_aya(ctx: TracePointContext) -> u32 {
    match try_test_aya(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret as u32,
    }
}

fn try_test_aya(ctx: TracePointContext) -> Result<u32, i64> {
    // let filename_src_addr = unsafe {ctx.read_at::<*const u8>(FILENAME_OFFSET)?};
    
    // Use the per-CPU array map instead of stack allocation to avoid BPF stack limit
    let buf =  BUF.get_ptr_mut(0).ok_or(0i64)?;
    
    // let filename_bytes: &[u8] = unsafe {
    //     aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?
    // };
    
    // let _filename = unsafe {
    //     core::str::from_utf8_unchecked(filename_bytes)
    // };
    
    let _filename = unsafe {
        *buf = [0u8;512]; // for reset the buffer 
        let filename_src_addr = ctx.read_at::<*const u8>(FILENAME_OFFSET)?;
        let filename_bytes = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_src_addr, &mut *buf)?;
        if EXCLUDED_CMDS.get(& *buf).is_some() {
            info!(&ctx, "No log for this Binary");
            return Ok(0);
        }
        core::str::from_utf8_unchecked(filename_bytes)
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
