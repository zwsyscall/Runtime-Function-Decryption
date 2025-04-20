#[macro_export]
macro_rules! encrypted_call {
    ($func:path, $($arg:expr), *) => {{
        {
            let function_body_start = unsafe { ($func as *mut u8).add(2) };
            let mut old_protect = windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE;

            // Save old protections
            unsafe {
                windows::Win32::System::Memory::VirtualProtect(
                    $func as *const c_void,
                    6,
                    windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                    &mut old_protect as *mut _,
                ).unwrap()
            };

            // Decrypt the bytes containing the function's length
            crypto::chacha20_operate_in_place(function_body_start, 4, 4, *keys::KEY, *keys::NONCE);

            // Read the function's length
            let function_length = unsafe {
                let length_bytes = std::mem::ManuallyDrop::new(Vec::from_raw_parts(function_body_start, 4, 4));
                u32::from_le_bytes(length_bytes.as_slice().try_into().unwrap()) as usize
            };

            // Modify the protections on the rest of the function to be RWX
            unsafe {
                windows::Win32::System::Memory::VirtualProtect(
                    $func as *const c_void,
                    function_length,
                    windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
                    &mut windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0) as *mut _,
                ).unwrap()
            };

            // Modify the protections on the rest of the function to be RWX
            crypto::chacha20_operate_in_place(
                function_body_start,
                function_length - 2,
                function_length - 2,
                *keys::KEY,
                *keys::NONCE,
            );

            let r = $func($($arg), *);

            // Re-encrypt the size bytes so they are left intact for the next time
            crypto::chacha20_operate_in_place(function_body_start, 4, 4, *keys::KEY, *keys::NONCE);

            // Re-encrypt the whole function.
            crypto::chacha20_operate_in_place(
                function_body_start,
                function_length - 2,
                function_length - 2,
                *keys::KEY,
                *keys::NONCE,
            );

            // Return the old protections
            unsafe { windows::Win32::System::Memory::VirtualProtect($func as *const c_void, function_length, old_protect, &mut old_protect as *mut _).unwrap() };

            r
        }
    }};
}
