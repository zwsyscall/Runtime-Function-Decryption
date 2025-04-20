use std::arch::asm;
use windows::Win32::System::{Diagnostics::Debug::WriteProcessMemory, Memory::VirtualAllocEx, Threading::OpenProcess};

#[inline(never)]
#[export_name = "rdtsc"]
pub fn rdtsc() -> u64 {
    // Jump & padding
    unsafe {
        asm!("jmp 2f", "int 3", "int 3", "int 3", "int 3", "2:", options(nomem, nostack));
    }

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

#[inline(never)]
#[export_name = "inject_shellcode"]
pub fn inject_shellcode() -> anyhow::Result<()> {
    // Jump & padding
    unsafe {
        asm!("jmp 2f", "int 3", "int 3", "int 3", "int 3", "2:", options(nomem, nostack));
    }
    let shellcode_buffer: [u8; 256] = [0; 256];

    // More complex code
    let handle = unsafe {
        OpenProcess(
            windows::Win32::System::Threading::PROCESS_ALL_ACCESS,
            false,
            windows::Win32::System::Threading::GetCurrentProcessId(),
        )
    }?;

    let allocated_address = unsafe {
        VirtualAllocEx(
            handle,
            None,
            400,
            windows::Win32::System::Memory::VIRTUAL_ALLOCATION_TYPE(0x00001000 | 0x00002000),
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
        )
    };

    unsafe {
        WriteProcessMemory(
            handle,
            allocated_address,
            shellcode_buffer.as_ptr() as *const std::ffi::c_void,
            shellcode_buffer.len(),
            None,
        )?;
    }

    unsafe {
        windows::Win32::System::Threading::CreateRemoteThreadEx(handle, None, 0, Some(std::mem::transmute(allocated_address)), None, 0, None, None)?;
    }

    Ok(())
}

#[inline(never)]
#[export_name = "example_function"]
pub fn function_input_output_example(input_str: &str) -> String {
    // Jump & padding
    unsafe {
        asm!("jmp 2f", "int 3", "int 3", "int 3", "int 3", "2:", options(nomem, nostack));
    }
    format!("Foo {}", input_str)
}
