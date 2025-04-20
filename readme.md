# Runtime function decryption POC
This repo contains a POC for runtime function decryption done natively with Rust.

The function encryption uses a streaming cipher, in this case `ChaCha20` but it is trivial to modify the POC to use any streaming cipher. Block ciphers can also be used, although they require more set up.

This method aims to minimally modify the source code of a program, mainly relying on post-build scripts to encrypt the functions.

Encryption keys are created with `build.rs`.

# Usage
The encryption happens in the `build/post_build` build script. The build script relies on debug symbols to parse function names and lengths.

In order to call encrypted functions, you use the `encrypted_call!` macro. Provide a function pointer and the necessary arguments.

If you want to make your own functions, add them to the `encrypted_functions.rs` file, add the necessary `#[inline(never)]` and `#[export_name = "${FUNCTION_NAME}"]` and prepend them with the necessary stub: `jmp 2f` `int3` `int3` `int3` `int3`.

If you want to use another file, please change the `ENCRYPTED_FUNCTIONS` environmental variable in the `Makefile.toml`.

The maximum length of a single function is `4,294,967,295` bytes. This can be changed by increasing the number of padding bytes.

# Building
Install cargo make: `cargo install cargo-make`

To run compile and run the debug build: `cargo make debug`

To run compile and run the release build: `cargo make release`
