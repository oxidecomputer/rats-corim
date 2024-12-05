use ciborium::Value;
use clap::Parser;
use corim_experiments::{pretty_print, Comid, Corim, SignedCorim};
use std::path::PathBuf;

#[derive(Parser, Debug)]
enum Command {
    PrintCbor { path: PathBuf },
    PrintComid { path: PathBuf },
    PrintCorim { path: PathBuf },
    PrintSignedCorim { path: PathBuf },
    RoundTrip { path: PathBuf },
}

#[derive(Debug, Parser)]
struct Arg {
    #[clap(subcommand)]
    cmd: Command,
}

fn main() {
    let arg = Arg::parse();

    match arg.cmd {
        Command::PrintCbor { path } => {
            let b = std::fs::read(path).unwrap();
            let s: Value = ciborium::from_reader(&b[..]).unwrap();
            println!("{}", pretty_print(s));
        }
        Command::PrintComid { path } => {
            let b = std::fs::read(path).unwrap();
            let s: Comid = ciborium::from_reader(&b[..]).unwrap();
            println!("{:?}", s);
        }
        Command::PrintCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: Corim = ciborium::from_reader(&b[..]).unwrap();
            println!("{:?}", s);
        }
        Command::PrintSignedCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: SignedCorim = ciborium::from_reader(&b[..]).unwrap();
            println!("{:x?}", s);
        }
    }
}
