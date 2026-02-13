use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap, ProgramArray}, programs::TracePointContext,
};

use aya_log_ebpf::error;
use test_aya_common::MAX_PATH_LEN;

pub const ZEROED_ARRAY: [u8; MAX_PATH_LEN] = [0u8; MAX_PATH_LEN];

// #[map]
// pub static BUF: PerCpuArray<[u8; MAX_PATH_LEN]> = PerCpuArray::with_max_entries(1, 0);

// #[map]
// pub static BUF: LruHashMap<u32, [u8; MAX_PATH_LEN]> = LruHashMap::with_max_entries(16, 0);

#[map]
pub static EXCLUDED_CMDS: HashMap<[u8; 512], u8> = HashMap::with_max_entries(10, 0);

#[map]
pub static JUMP_TABLE: ProgramArray = ProgramArray::with_max_entries(2, 0);

// #[map]
// pub static T_ENTER: LruHashMap<u32,u64> = LruHashMap::with_max_entries(16,0);

#[repr(C)]
pub struct ProgramState {
    pub t_enter: u64,
    pub t_exit: u64,
    pub buffer: [u8; MAX_PATH_LEN],
    pub ret: i64,
}

#[map]
pub static PROGRAM: LruHashMap<u32, ProgramState> = LruHashMap::with_max_entries(16, 0);


#[inline(always)]
pub fn try_tail_call(ctx: &TracePointContext, index: u32) {
    let res = unsafe { JUMP_TABLE.tail_call(ctx, index) };
    if res.is_err() {
        error!(ctx, "exit: tail_call failed");
    }
}

pub const INIT_STATE: ProgramState = ProgramState {
    t_enter: 0,
    t_exit: 0,
    buffer: ZEROED_ARRAY,
    ret: 0,
};
