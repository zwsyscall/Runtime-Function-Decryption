use goblin::pe::PE;
use pdb::{FallibleIterator, SymbolData, PDB};
use std::env;
use std::fs::File;
use std::path::Path;

mod encryption;

#[derive(serde::Serialize)]
struct Function {
    name: String,
    address: u32,
    size: u32,
}

fn find_text_offset(path: &std::path::PathBuf) -> Option<(u32, u32)> {
    let buffer = std::fs::read(&path).unwrap();

    let pe = PE::parse(&buffer).unwrap();

    for section in &pe.sections {
        let name = section.name().unwrap_or("<invalid>");
        if name == ".text" {
            return Some((section.pointer_to_raw_data, section.size_of_raw_data));
        }
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary_name = "general_inj";
    let profile = "debug";
    let pdb_path = Path::new("target").join(&profile).join(format!("{}.pdb", &binary_name));
    let exe_path = Path::new("target").join(&profile).join(format!("{}.exe", &binary_name));

    let file = File::open(&pdb_path)?;
    let mut pdb = PDB::open(file)?;

    let address_map = pdb.address_map()?;

    let debug_info = pdb.debug_information()?;
    let mut modules = debug_info.modules()?;

    let mut functions = Vec::new();

    let (text_offset, _text_size) = find_text_offset(&exe_path).unwrap();

    while let Some(module) = modules.next()? {
        if let Some(module_info) = pdb.module_info(&module)? {
            let mut symbols = module_info.symbols()?;

            while let Some(symbol) = symbols.next()? {
                match symbol.parse() {
                    Ok(SymbolData::Procedure(data)) => {
                        let name = data.name.to_string();
                        let size = data.len;
                        let rva = data.offset.to_rva(&address_map).unwrap().0;
                        if name.contains("evasion") {
                            println!("Adding {} to be encrypted", name);
                            functions.push(Function {
                                name: name.into(),
                                address: rva - 0x1000 + text_offset,
                                size: size,
                            });
                        }
                    }

                    Ok(_) => { /* skip */ }

                    Err(pdb::Error::UnimplementedSymbolKind(kind)) => {
                        continue;
                    }

                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let mut file_handle = File::options().read(true).write(true).open(exe_path)?;
    let key = b"testestestestestestestestesteste";
    let paedophile = b"testestestes";

    for function in functions {
        println!("Encrypting {} at {:0x}", &function.name, &function.address);
        encryption::encrypt_function(&mut file_handle, function.address.into(), function.size as usize, &key, &paedophile)?;
    }

    Ok(())
}
