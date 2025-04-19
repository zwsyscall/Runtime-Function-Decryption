// https://microsoft.github.io/windows-rs/features/#/0.59.0/search
use std::{arch::asm, hint::black_box};
use windows::Win32::System::{
    Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT},
    Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT},
};

#[inline(never)]
#[export_name = "rdtsc"]
pub extern "C" fn rdtsc() -> u64 {
    let mut edx: u32;
    let mut eax: u32;
    unsafe {
        asm!(
            "MFENCE",
            "LFENCE",
            "rdtsc",
            out("edx") edx,
            out("eax") eax,
        );
    }
    ((edx as u64) << 32) | (eax as u64)
}

pub fn cpu_timing() -> usize {
    let time_1 = rdtsc();
    black_box(1 + 5);
    let time_2 = rdtsc();
    (time_2 - time_1) as usize
}

pub fn get_main_thread_id() -> usize {
    let thread_id: usize;
    unsafe {
        asm!(
            "mov {0}, gs:[0x30]", // Load TEB base into x
            "add {0}, 0x48",      // Add offset to ClientId.UniqueThread
            lateout(reg) thread_id,
        );
    }
    thread_id
}

pub fn clear_hw_breakpoints() -> anyhow::Result<()> {
    let main_thred_id: u32 = get_main_thread_id().try_into()?;
    let thread_handle = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, main_thred_id) }?;

    // Compiler doesn't understand
    #[allow(unused_mut)]
    let mut thread_context: *mut CONTEXT = std::ptr::null_mut();
    unsafe {
        GetThreadContext(thread_handle, thread_context)?;
        (*thread_context).Dr0 = 0;
        (*thread_context).Dr1 = 0;
        (*thread_context).Dr2 = 0;
        (*thread_context).Dr3 = 0;
        SetThreadContext(thread_handle, thread_context)?;
    }

    Ok(())
}

fn encrypted_call<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}
