This crate simplifies the compilation of eBPF programs written in C integrating clang with Rust and the cargo build system with functions that can be used from a `build.rs` file. It can also embed those ELF files as lazy_statically loaded u8 slices that can be then executed directly from memory with crates such as [Aya](https://github.com/alessandrod/aya).

Include paths and other architecture specific information are automatically detected on the host machine so that no manual configuration is required. However each parameter can be customized by setting an environment variable.

| Variable                               | Default                          | Description                 |
| -------------------------------------- | -------------------------------- | --------------------------- |
| `CLANG_EBPF_BUILDER_LINUX_KERNEL_BASE` | `/lib/modules/${uname -r}/build` | Kernel headers path.        |
| `CLANG_EBPF_BUILDER_LINUX_ARCH`        | `uname -m`                       | Target architecture.        |
| `CLANG_EBPF_BUILDER_LINUX_TRIPLET`     | `gcc -dumpmachine`               | Target compilation triplet. |
| `CLANG_EBPF_BUILDER_CLANG_INCLUDE`     | `clang -print-file-name=include` | CLang include path.         |
| `CLANG_EBPF_BUILDER_USER_INCLUDE`      | `/usr/include/<target triplet>`  | Userland include path.      |

### Example

A fully working example is provided inside the `example` folder. Assuming you have `clang` installed, you can just `cargo build` it and it will produce a single executable containing both the userland loading code and the actual eBPF program. Once you'll run it as root, you will see what system calls each process is executing in realtime.

You will notice there are no Makefiles or other forms of build configuration because everything is contained inside the `build.rs` file using the `builder` crate functionalities. The `src/example.c` program is compiled and then embedded inside `src/example.rs`. The ELF buffer is then loaded by accessing `example::DATA`.

### License

Released under the GPL 3 license.