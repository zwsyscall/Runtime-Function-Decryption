use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};

pub fn encrypt_function(file: &mut File, offset: u64, len: usize, key: &[u8; 32], nonce: &[u8; 12]) -> anyhow::Result<()> {
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; len];
    // Read the function's body to buffer
    file.read_exact(&mut buffer)?;

    // Move the function's initial jump stub
    move_stub(&mut buffer);
    encode_function_length(&mut buffer, len);

    // In place ChaCha20 encryption.
    encrypt_chunk(&mut buffer[2..], key, nonce);

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&buffer)?;
    Ok(())
}

fn encrypt_chunk(buffer: &mut [u8], key: &[u8; 32], nonce: &[u8; 12]) {
    let mut cipher = ChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(buffer);
}

fn move_stub(function_bytes: &mut Vec<u8>) {
    // Four bytes are used as the buffer for the function's length.
    let stub_signature: [u8; 6] = [0xeb, 0x04, 0xcc, 0xcc, 0xcc, 0xcc];

    // Find the stub in the function's bytes
    let stub_offset = function_bytes
        .windows(stub_signature.len())
        .position(|window| window == stub_signature)
        .expect("[!] No function stub signature found!");

    // Remove the stub
    function_bytes.drain(stub_offset..stub_offset + stub_signature.len());

    // Push them to the start
    function_bytes.splice(0..0, stub_signature);
}

fn encode_function_length(stub_bytes: &mut Vec<u8>, function_length: usize) {
    if function_length > u32::MAX as usize {
        panic!("[!] Function length wont fit in stub");
    }
    let encoded_length = (function_length as u32).to_le_bytes();
    // Overwrite the function length bytes with the appropriate length.
    // This assumes that the functions are after a jmp instruction, hence the 2..6
    stub_bytes[2..6].copy_from_slice(&encoded_length);
}
