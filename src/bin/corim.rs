// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use ciborium::Value;
use clap::Parser;
use rats_corim::{pretty_print, Comid, Corim, CorimBuilder, SignedCorim};
use sha3::{Digest, Sha3_256};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[allow(clippy::enum_variant_names)]
enum Command {
    PrintCbor {
        path: PathBuf,
    },
    PrintComid {
        path: PathBuf,
    },
    PrintCorim {
        path: PathBuf,
    },
    PrintSignedCorim {
        path: PathBuf,
    },
    GenerateCorim {
        #[clap(long)]
        id: String,
        #[clap(long)]
        tag_id: String,
        #[clap(long)]
        version: String,
        #[clap(long)]
        vendor: String,
        #[clap(long)]
        file: Vec<PathBuf>,
        #[clap(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Parser)]
struct Arg {
    #[clap(subcommand)]
    cmd: Command,
}

fn main() -> Result<()> {
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
            println!("{s}");
        }
        Command::PrintCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: Corim = ciborium::from_reader(&b[..]).unwrap();
            println!("{s}");
        }
        Command::PrintSignedCorim { path } => {
            let b = std::fs::read(path).unwrap();
            let s: SignedCorim = ciborium::from_reader(&b[..]).unwrap();
            println!("{s:x?}");
        }
        Command::GenerateCorim {
            id,
            tag_id,
            version,
            vendor,
            file,
            out,
        } => {
            let mut builder = CorimBuilder::new();

            builder.vendor(vendor);
            builder.tag_id(tag_id);
            builder.version(version);
            builder.id(id);

            for f in file {
                let name = f.file_name().unwrap().to_str().unwrap().to_string();
                let b = std::fs::read(f)?;

                let mut hasher = Sha3_256::new();
                hasher.update(&b);
                let result = hasher.finalize();
                builder.add_hash(name, 10, result.to_vec());
            }

            let corim = builder.build()?;

            std::fs::write(&out, corim.to_vec()?)?;
            println!("wrote to {}", out.display());
        }
    }

    Ok(())
}
