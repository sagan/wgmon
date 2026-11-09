use libbpf_cargo::SkeletonBuilder;
use std::env;
use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for name in ["kprobe", "tc"] {
        let src = format!("src/bpf/{name}.bpf.c");
        println!("cargo:rerun-if-changed={src}");
        println!("cargo:rerun-if-changed=src/bpf/common.h");
        println!("cargo:rerun-if-changed=src/bpf/types.h");
        SkeletonBuilder::new()
            .source(&src)
            .clang_args(["-Isrc/bpf"])
            .build_and_generate(out.join(format!("{name}.skel.rs")))
            .unwrap();
    }
}
