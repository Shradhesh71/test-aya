use aya::{maps::ProgramArray, programs::TracePoint};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use aya::maps::{HashMap, MapData};

mod common;
use crate::common::*;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/test-aya"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let program: &mut TracePoint = ebpf.program_mut("tracepoint_binary").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

    let program: &mut TracePoint = ebpf.program_mut("tracepoint_binary_exit").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_exit_execve")?;


    let map = ebpf.map_mut("EXCLUDED_CMDS").unwrap();
    let mut excluded_cmds :HashMap<&mut MapData, [u8;512], u8> = HashMap::try_from(map)?;
    for cmd in EXCLUDE_LISTS.iter() {
        let cmd_zero = cmd_to_bytes(cmd);
        excluded_cmds.insert(cmd_zero, 1, 0)?;
    }

    //  add ebpf tail maps
    let map = ebpf.take_map("JUMP_TABLE").unwrap();
    let mut tail_call_map = ProgramArray::try_from(map)?;

    // let prog_0: &mut TracePoint = ebpf.program_mut("tracepoint_binary_filter").unwrap().try_into()?;
    // prog_0.load()?;
    // let prog_0_fd = prog_0.fd().unwrap();
    // tail_call_map.set(0, &prog_0_fd, 0)?;



    let prg_list = ["test_aya_filter", "test_aya_display"];

    for (i, prg) in prg_list.iter().enumerate() {
        {
            let program: &mut TracePoint = ebpf.program_mut(prg).unwrap().try_into()?;
            program.load()?;
            let fd = program.fd().unwrap();
            tail_call_map.set(i as u32, fd, 0)?;
        }
    }



    
    

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn cmd_to_bytes(cmd: &str) -> [u8; 512] {
    let mut cmd_zero = [0u8; 512];
    let cmd_bytes = cmd.as_bytes();
    let len = cmd_bytes.len();
    cmd_zero[..len].copy_from_slice(cmd_bytes);
    cmd_zero
}