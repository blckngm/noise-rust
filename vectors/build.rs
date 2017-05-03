// build.rs

use std::env;
use std::fs::File;
use std::io::copy;
use std::path::Path;
use std::process::{Command, Stdio};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let script_path = Path::new(&manifest_dir).join("tests").join("gen.py");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("crypto_impls.rs");
    let mut out_file = File::create(&dest_path).unwrap();

    let mut child = Command::new("python3")
        .arg(script_path).stdout(Stdio::piped()).spawn().unwrap();

    copy(child.stdout.as_mut().unwrap(), &mut out_file).unwrap();

    assert!(child.wait().unwrap().success());
}
