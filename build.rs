use ethers::prelude::Abigen;
use eyre::Result;

const CONTRACT_NAME: &str = "DataAvailabilityChallenge";

fn main() -> Result<()> {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let out_file = std::path::Path::new(&out_dir).join("contract_bindings.rs");

    if out_file.exists() {
        return Ok(());
    }

    let bindings = Abigen::new(CONTRACT_NAME, "./DataAvailabilityChallenge.json")?.generate()?;

    println!("out_file: {:?}", out_file);
    bindings.write_to_file(out_file)?;

    Ok(())
}
