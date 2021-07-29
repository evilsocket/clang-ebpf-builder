use std::fs;
use std::path::PathBuf;

fn main() {
	// tell cargo to rebuild only if src/example.c changed
	println!("cargo:rerun-if-changed=src/example.c");

	// add our include folder to the include paths.
	let include = fs::canonicalize(&PathBuf::from("include")).unwrap();

	// build src/example.c into example.o and then embed it into src/probe.rs
	clang_ebpf_builder::build_to_code("src/example.c", "example.o", Some(include), "src/example.rs").unwrap();
}
