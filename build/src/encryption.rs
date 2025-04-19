use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use std::fs::File;
use std::io::Read;
use std::io::{Seek, SeekFrom, Write};

pub fn encrypt_function(file: &mut File, offset: u64, len: usize, key: &[u8; 32], nonce: &[u8; 12]) -> anyhow::Result<()> {
    // Jump to the right position
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = vec![0u8; len];
    file.read_exact(&mut buffer)?;

    let mut cipher = ChaCha20::new(key.into(), nonce.into());

    cipher.apply_keystream(&mut buffer);

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&buffer)?;
    Ok(())
}
