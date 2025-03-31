// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use ciborium::Value;
use clap::Parser;
use corim_experiments::{pretty_print, Comid, Corim, SignedCorim};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[allow(clippy::enum_variant_names)]
enum Command {
    PrintCbor { path: PathBuf },
    PrintComid { path: PathBuf },
    PrintCorim { path: PathBuf },
    PrintSignedCorim { path: PathBuf },
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
            println!("{}", s);
        }
        Command::PrintCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: Corim = ciborium::from_reader(&b[..]).unwrap();
            println!("{}", s);
        }
        Command::PrintSignedCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: SignedCorim = ciborium::from_reader(&b[..]).unwrap();
            println!("{:x?}", s);
        }
    }
}
