#![no_std]
#![no_main]

mod common;
mod hook;
mod filter;
mod display;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
