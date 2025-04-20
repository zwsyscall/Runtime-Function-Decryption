use rand::Rng;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = "src\\";
    let dest_path = Path::new(&out_dir).join("keys.rs");
    println!("cargo:rerun-if-changed=build.rs");
    let mut rng = rand::rng();

    let charset = b"abcdefghijklmnopqrstuvwxyz-_+123456789";

    let key: String = (0..32)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let nonce: String = (0..12)
        .map(|_| {
            let idx = rng.random_range(0..charset.len());
            charset[idx] as char
        })
        .collect();

    let contents = format!(
        "pub static KEY: &[u8; 32] = b\"{key}\";\npub static NONCE: &[u8; 12] = b\"{nonce}\";",
        key = key,
        nonce = nonce,
    );

    fs::write(dest_path, contents).unwrap();
}
