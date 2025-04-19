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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_in_place() {
        let mut test_vector = Vec::from("Hi! How is it going guys. This is a test message :^)".as_bytes());
        let key = b"This key is super secret! Nope !";
        let nonce = b"Hi, I'm test";
        assert!(encrypt_in_place(&mut test_vector, *key, *nonce).is_ok());
        assert_eq!(
            test_vector,
            [
                19, 144, 7, 211, 232, 102, 10, 206, 115, 244, 158, 30, 161, 230, 38, 13, 104, 4, 169, 124, 232, 128, 22, 185, 171, 136, 33, 62, 110, 227, 225, 118, 80, 144, 71,
                133, 212, 93, 66, 75, 73, 11, 250, 121, 255, 86, 156, 101, 243, 71, 134, 159, 218, 199, 108, 118, 148, 251, 202, 192, 176, 200, 76, 11, 130, 160, 20, 33
            ]
        )
    }

    #[test]
    fn test_decrypt_in_place() {
        let mut test_vector = vec![
            19, 144, 7, 211, 232, 102, 10, 206, 115, 244, 158, 30, 161, 230, 38, 13, 104, 4, 169, 124, 232, 128, 22, 185, 171, 136, 33, 62, 110, 227, 225, 118, 80, 144, 71, 133,
            212, 93, 66, 75, 73, 11, 250, 121, 255, 86, 156, 101, 243, 71, 134, 159, 218, 199, 108, 118, 148, 251, 202, 192, 176, 200, 76, 11, 130, 160, 20, 33,
        ];
        let key = b"This key is super secret! Nope !";
        let nonce = b"Hi, I'm test";
        assert!(decrypt_in_place(&mut test_vector, *key, *nonce).is_ok());
        assert_eq!(test_vector, "Hi! How is it going guys. This is a test message :^)".as_bytes())
    }

    #[test]
    fn test_decrypt_in_memory() {
        use std::mem::ManuallyDrop;
        use std::slice;

        // prevent double free because (decrypt_memory takes ownership of this memory region)
        let mut test_vector = ManuallyDrop::new(vec![
            19, 144, 7, 211, 232, 102, 10, 206, 115, 244, 158, 30, 161, 230, 38, 13, 104, 4, 169, 124, 232, 128, 22, 185, 171, 136, 33, 62, 110, 227, 225, 118, 80, 144, 71, 133,
            212, 93, 66, 75, 73, 11, 250, 121, 255, 86, 156, 101, 243, 71, 134, 159, 218, 199, 108, 118, 148, 251, 202, 192, 176, 200, 76, 11, 130, 160, 20, 33,
        ]);

        let key = *b"This key is super secret! Nope !";
        let nonce = *b"Hi, I'm test";
        assert!(decrypt_memory(test_vector.as_mut_ptr(), test_vector.len(), test_vector.capacity(), key, nonce).is_ok());

        // We reduce the length by 16 here to remove the tag_len
        let plaintext_len = test_vector.len().checked_sub(16).expect("ciphertext must be at least TAG_LEN bytes");
        let plaintext: &[u8] = unsafe { slice::from_raw_parts(test_vector.as_mut_ptr(), plaintext_len) };

        assert_eq!(plaintext, b"Hi! How is it going guys. This is a test message :^)");
    }

    #[test]
    fn test_sha256_sum() {
        let known_sum = vec![
            236, 215, 24, 112, 209, 150, 51, 22, 169, 126, 58, 195, 64, 140, 152, 53, 173, 140, 240, 243, 193, 188, 112, 53, 39, 195, 2, 101, 83, 79, 117, 174,
        ];
        let word = b"test123";
        assert!(checksum(word, &known_sum));
    }
}
