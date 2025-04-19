use aes_gcm::{
    aead::{AeadMutInPlace, KeyInit},
    Aes256Gcm, Key,
};
use sha2::{Digest, Sha256};

use anyhow::bail;

pub fn checksum(data: &[u8], checksum: &[u8]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let created_hash = hasher.finalize().to_vec();
    &created_hash == checksum
}

pub fn decrypt_memory(ptr: *mut u8, len: usize, capacity: usize, key: [u8; 32], nonce: [u8; 12]) -> anyhow::Result<()> {
    let mut data_vector = unsafe { Vec::from_raw_parts(ptr, len, capacity) };
    match decrypt_in_place(&mut data_vector, key, nonce) {
        Err(e) => bail!("{}", e),
        Ok(_) => Ok(()),
    }
}

pub fn decrypt_in_place(block: &mut Vec<u8>, key: [u8; 32], nonce: [u8; 12]) -> Result<(), aes_gcm::Error> {
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);
    let mut cipher = Aes256Gcm::new(&aes_key);
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce);

    cipher.decrypt_in_place(nonce, b"", block)?;
    Ok(())
}

pub fn encrypt_in_place(block: &mut Vec<u8>, key: [u8; 32], nonce: [u8; 12]) -> Result<(), aes_gcm::Error> {
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);
    let mut cipher = Aes256Gcm::new(&aes_key);
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(&nonce);

    cipher.encrypt_in_place(nonce, b"", block)?;
    Ok(())
}

