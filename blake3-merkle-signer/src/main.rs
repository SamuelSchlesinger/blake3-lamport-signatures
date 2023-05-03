use blake3_lamport_signatures::{lamport, merkle};

use clap::{Parser, Subcommand};
use std::{
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

#[derive(Parser, Debug)]
struct Arguments {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    KeyGen {
        private_key: PathBuf,
        public_key: PathBuf,
        num_messages: usize,
    },
    Sign {
        message: PathBuf,
        private_key: PathBuf,
        signature: PathBuf,
    },
    Verify {
        message: PathBuf,
        signature: PathBuf,
        public_key: PathBuf,
    },
}

pub fn read_message(file: PathBuf) -> std::io::Result<Vec<u8>> {
    let mut f = File::options().read(true).open(file)?;
    let mut msg = Vec::new();
    f.read_to_end(&mut msg)?;

    Ok(msg)
}

pub fn read_public_key(file: PathBuf) -> std::io::Result<merkle::PublicKey> {
    let f = File::options().read(true).open(file)?;
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 40];
    reader.read(&mut buf)?;

    Ok(buf.into())
}

pub fn read_private_key(file: PathBuf) -> std::io::Result<merkle::PrivateKey> {
    let f = File::options().read(true).open(file)?;
    let mut reader = BufReader::new(f);
    let mut buf = [0u8; 16384];
    let mut private_keys: Vec<lamport::PrivateKey> = vec![];
    while let Ok(private_key_length) = reader.read(&mut buf) {
        if private_key_length != 16384 {
            if private_key_length == 8 {
                let mut inner_buf = [0u8; 8];
                for i in 0..8 {
                    inner_buf[i] = buf[i];
                }
                let current_index = u64::from_be_bytes(inner_buf) as usize;
                return Ok((private_keys, current_index).into());
            }
        }
        private_keys.push((&buf).into());
    }
    panic!("fucko");
}

pub fn read_signature(file: PathBuf) -> std::io::Result<merkle::Signature> {
    let mut signature_bytes = Vec::new();
    let mut f: File = File::options().read(true).open(file)?;
    f.read_to_end(&mut signature_bytes)?;
    let signature_bytes_ref: &[u8] = &signature_bytes;
    Ok(signature_bytes_ref.try_into().unwrap())
}

pub fn write_signature(signature: &merkle::Signature, file: PathBuf) -> std::io::Result<()> {
    let mut f: File = File::options().create(true).write(true).open(file)?;
    f.write_all(&Vec::from(signature))?;
    Ok(())
}

pub fn write_private_key(private_key: merkle::PrivateKey, file: PathBuf) -> std::io::Result<()> {
    let f = File::options().create(true).write(true).open(file)?;
    let mut writer = BufWriter::new(f);
    for private_key in private_key.inner_keys() {
        let buf: [u8; 16384] = private_key.into();
        writer.write(&buf)?;
    }
    writer.write(&(private_key.current_index() as u64).to_be_bytes())?;
    Ok(())
}

pub fn write_public_key(public_key: merkle::PublicKey, file: PathBuf) -> std::io::Result<()> {
    let f = File::options().create(true).write(true).open(file)?;
    let mut writer = BufWriter::new(f);
    let buf: [u8; 40] = public_key.into();
    writer.write(&buf)?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args = Arguments::parse();
    use Command::*;
    match args.cmd {
        KeyGen {
            private_key,
            public_key,
            num_messages,
        } => {
            let privk = merkle::PrivateKey::generate(num_messages).unwrap();
            let pubk = privk.public_key();
            write_private_key(privk, private_key)?;
            write_public_key(pubk, public_key)?;
        }
        Sign {
            message,
            private_key,
            signature,
        } => {
            let mut privk = read_private_key(private_key.clone())?;
            let message = read_message(message)?;
            let mut signature_file = File::options()
                .create(true)
                .write(true)
                .open(signature)
                .expect("open signature file");
            if let Some(signature) = privk.sign(&message) {
                let signature_vec: Vec<u8> = (&signature).into();
                let signature_vec_bytes: &[u8] = &signature_vec;
                signature_file.write_all(signature_vec_bytes)?;
                write_private_key(privk, private_key)?;
            } else {
                eprintln!("ran out of signatures for this private key");
            }
        }
        Verify {
            message,
            signature,
            public_key,
        } => {
            let pubk = read_public_key(public_key)?;
            let signature = read_signature(signature)?;
            let message = read_message(message)?;
            println!("signature validity: {}", pubk.verify(message, &signature));
        }
    }
    Ok(())
}
