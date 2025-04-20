use std::mem::ManuallyDrop;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

pub fn chacha20_operate_in_place(ptr: *mut u8, len: usize, capacity: usize, key: [u8; 32], nonce: [u8; 12]) {
    let mut buffer = ManuallyDrop::new(unsafe { Vec::from_raw_parts(ptr, len, capacity) });

    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());
    cipher.apply_keystream(&mut buffer);
}
