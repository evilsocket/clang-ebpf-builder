use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::{prelude::*, BufReader};

use aya::{Bpf, Btf, programs::TracePoint};

mod example;

const TRACING_ENABLE: &str = "/sys/kernel/debug/tracing/tracing_on";
const TRACING_PIPE: &str = "/sys/kernel/debug/tracing/trace_pipe";

fn main() {
    println!("loading {} bytes of eBPF program ...", example::DATA.len());

    let mut bpf = Bpf::load(&example::DATA, Btf::from_sys_fs().ok().as_ref()).unwrap();

    println!("registering tracepoint ...");

    let tp: &mut TracePoint = bpf.program_mut("on_sys_enter").unwrap().try_into().unwrap();
    
    // load it
    tp.load().unwrap();
      // attach it
    tp.attach("raw_syscalls", "sys_enter").unwrap();

    // now enable tracing and read the logs
    fs::write(TRACING_ENABLE, "1").unwrap();

    let file = File::open(TRACING_PIPE).unwrap();
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line) {
          Ok(read) => {
            if read == 0 {
              break;
            }
            println!("{}", line);
          }
          Err(err) => {
            println!("error reading {}: {}", TRACING_PIPE, err);
          }
        };
    }
}
