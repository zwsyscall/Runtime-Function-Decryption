mod crypto;
mod encrypted_functions;
pub mod evasion;
pub mod keys;

fn main() -> anyhow::Result<()> {
    // Performance test
    let rdtsc_1 = encrypted_call!(encrypted_functions::rdtsc,);
    println!("[+] rdtsc: {}", rdtsc_1);
    let rdtsc_2 = encrypted_call!(encrypted_functions::rdtsc,);
    println!("[+] diff: {}", rdtsc_2 - rdtsc_1);

    // Longer function
    encrypted_call!(encrypted_functions::inject_shellcode,)?;

    // Input and output
    let function_output = encrypted_call!(encrypted_functions::function_input_output_example, "bar");
    println!("[+] Function output: {}", function_output);
    Ok(())
}
