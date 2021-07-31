use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn run(bin: &str, args: &[&str]) -> String {
    String::from_utf8_lossy(
        &Command::new(bin)
            .args(args)
            .output()
            .expect(&format!("failed to execute {} {:?}", bin, args))
            .stdout,
    )
    .trim()
    .to_owned()
}

fn env_or(var_name: &str, or: String) -> String {
    match env::var_os(var_name) {
        Some(s) => String::from(
            s.to_str()
                .expect(&format!("could not convert {} to string", var_name)),
        ),
        None => or,
    }
}

/// Stores paths used by clang to compile an eBPF program.
pub struct BuildContext {
    /// Kernel headers path. Set via CLANG_EBPF_BUILDER_LINUX_KERNEL_BASE or /lib/modules/${uname -r}/build
    pub kernel_base: String,
    /// Target architecture. Set via CLANG_EBPF_BUILDER_LINUX_ARCH or uname -m
    pub arch: String,
    /// Target compilation triplet. Set via CLANG_EBPF_BUILDER_LINUX_TRIPLET or gcc -dumpmachine
    pub triplet: String,
    /// CLang include path (for builtins). Set via CLANG_EBPF_BUILDER_CLANG_INCLUDE or clang -print-file-name=include
    pub clang_include: String,
    /// Userland include path. Set via CLANG_EBPF_BUILDER_USER_INCLUDE or /usr/include/<target triplet>
    pub user_include: String,
    /// Optional user specified include path. If set it allows users to specify custom include paths (for instance, bpf_helpers.h).
    pub local_include: Option<String>,
}

impl BuildContext {
    pub(crate) fn new(local_include: Option<PathBuf>) -> Self {
        // base include path for kernel headers
        let kernel_base = env_or(
            "CLANG_EBPF_BUILDER_LINUX_KERNEL_BASE",
            format!("/lib/modules/{}/build/", run("uname", &["-r"])),
        );
        // includes architecture
        let arch = env_or(
            "CLANG_EBPF_BUILDER_LINUX_ARCH",
            run("uname", &["-m"])
                .replace("x86_64", "x86")
                .replace("i386", "x86"),
        );
        // clang includes
        let clang_include = env_or(
            "CLANG_EBPF_BUILDER_CLANG_INCLUDE",
            run("clang", &["-print-file-name=include"]),
        );
        // host triplet
        let triplet = env_or(
            "CLANG_EBPF_BUILDER_LINUX_TRIPLET",
            run("gcc", &["-dumpmachine"]), // TODO: find a way to remove the gcc dependency
        );
        // userland includes for the specific host triplet
        let user_include = env_or(
            "CLANG_EBPF_BUILDER_USER_INCLUDE",
            format!("/usr/include/{}", triplet),
        );
        // optional local bpf includes
        let local_include = match local_include {
            Some(path) => Some(path.into_os_string().into_string().unwrap()),
            None => None,
        };

        Self {
            kernel_base,
            arch,
            triplet,
            clang_include,
            user_include,
            local_include,
        }
    }
}

/// Compiles the C eBPF program `input` into the `output` ELF file using clang.
/// If the `includes` path is set, it will be added to the include paths.
pub fn build(input: &str, output: &str, includes: Option<PathBuf>) -> Result<BuildContext, String> {
    let ctx = BuildContext::new(includes);
    // intermediate file
    let intermedate = format!("{}.ll", &output);

    // NOTE: we *have* to do this in two steps, otherwise we'd get compilation errors
    // related to the architecture not propagated in the compile chain when we include
    // certain headers such as linux/ptrace.h
    // See:
    //  - https://github.com/iovisor/bcc/issues/2578
    //  - https://lore.kernel.org/patchwork/patch/663307/

    let user_inc = match ctx.local_include {
        Some(ref s) => s.to_owned(),
        None => ".".to_owned(), // just a fallback value
    };

    // first compile to llvm ir
    let clang = Command::new("clang")
        .args(&["-S", "-nostdinc", "-isystem", &ctx.clang_include])
        .args(&[
            "-I",
            &format!(
                "{}/arch/{}/include/generated/uapi",
                ctx.kernel_base, ctx.arch
            ),
        ])
        .args(&[
            "-I",
            &format!("{}/arch/{}/include/generated", ctx.kernel_base, ctx.arch),
        ])
        .args(&[
            "-I",
            &format!("{}/arch/{}/include", ctx.kernel_base, ctx.arch),
        ])
        .args(&[
            "-I",
            &format!("{}/arch/{}/include/uapi", ctx.kernel_base, ctx.arch),
        ])
        .args(&["-I", &format!("{}/include", ctx.kernel_base)])
        .args(&["-I", &format!("{}/include/uapi", ctx.kernel_base)])
        .args(&[
            "-include",
            &format!("{}/include/linux/kconfig.h", ctx.kernel_base),
        ])
        .args(&["-I", &format!("{}/include/generated/uapi", ctx.kernel_base)])
        .args(&["-I", &user_inc])
        .args(&["-I", &ctx.user_include])
        .args(&["-I", "/usr/include/"]) // standard userland includes
        .arg("-Wno-everything")
        .arg("-fno-stack-protector") // avoids "A call to built-in function '__stack_chk_fail' is not supported."
        .arg("-fno-jump-tables")
        .arg("-fno-unwind-tables")
        .arg("-fno-asynchronous-unwind-tables")
        .args(&["-D", "__KERNEL__"])
        .args(&["-D", "__ASM_SYSREG_H"])
        .args(&["-D", "__BPF_TRACING__"])
        .args(&["-D", "KBUILD_MODNAME=\"clang-built-ebpf-module\""])
        .args(&["-D", &format!("__TARGET_ARCH_{}", ctx.arch)])
        .arg("-O2")
        .arg("-emit-llvm")
        .args(&["-c", input])
        .args(&["-o", &intermedate])
        .output()
        .expect("ebpf program compilation failed");

    let out = String::from_utf8_lossy(&clang.stdout);
    let err = String::from_utf8_lossy(&clang.stderr);

    if !out.trim().is_empty() {
        return Err(out.into_owned());
    }

    if !err.trim().is_empty() {
        return Err(err.into_owned());
    }

    // then convert to bpf assembly
    let llc = Command::new("llc")
        .arg("-march=bpf")
        .arg("-filetype=obj")
        .args(&["-o", output])
        .arg(&intermedate)
        .output()
        .expect("ebpf program linking failed");

    let out = String::from_utf8_lossy(&llc.stdout);
    let err = String::from_utf8_lossy(&llc.stderr);

    if !out.trim().is_empty() {
        return Err(out.into_owned());
    }

    if !err.trim().is_empty() {
        return Err(err.into_owned());
    }

    Ok(ctx)
}

/// Compiles the C eBPF program `input` into the OUT_DIR/`output_object_name` ELF file using clang.
/// Then it'll embed this object file as a slice of u8 inside `output_source`.
/// If the `includes` path is set, it will be added to the include paths.
pub fn build_to_code(
    input: &str,
    ouput_object_name: &str,
    includes: Option<PathBuf>,
    output_source: &str,
) -> Result<BuildContext, String> {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let output_object = format!("{}/{}", out_dir.to_str().unwrap(), &ouput_object_name);

    // compile to ELF object
    let ctx = build(input, &output_object, includes)?;

    // read the object file
    let data = fs::read(&output_object).expect(&format!("can't read {}", &output_object));

    // inline it as a slice of u8
    let mut f = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(output_source)
        .expect(&format!("can't open {}", output_source));

    let code: String = data.iter().map(|&b| format!("{:#01x}", b) + ",").collect();
    f.write_all(
		  format!(
			  "/// Automatically generated for: kernel_base={} arch={} triplet={} - DO NOT EDIT.\n\nuse lazy_static::lazy_static;\nlazy_static! {{\n  pub static ref DATA: Vec<u8> = vec![{}];\n}}",
			  ctx.kernel_base,
        ctx.arch,
        ctx.triplet,
        code.trim_end_matches(',')
		  )
		  .as_bytes(),
	  )
	  .unwrap();
    f.flush().unwrap();

    Ok(ctx)
}
