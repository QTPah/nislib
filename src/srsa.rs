use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::{RsaPrivateKey, RsaPublicKey};

use std::io::{Read, Write};
use std::io::BufReader;
use std::fs::File;

pub fn generate_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let bits = 2048;
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = private_key.to_public_key();

    (private_key, public_key)
}

pub fn encrypt(key : RsaPublicKey, data : Vec<u8>) -> Result<Vec<u8>, &'static str> {

    let mut rng = OsRng;
    let mut buffer = Vec::new();

    data.chunks(245).for_each(|chunk| {
        let encrypted = key.encrypt(&mut rng, rsa::Pkcs1v15Encrypt, chunk).unwrap();
        buffer.extend_from_slice(&encrypted);
    });

    Ok(buffer)
}

pub fn decrypt(key : RsaPrivateKey, data : Vec<u8>) -> Result<Vec<u8>, &'static str> {
    
    let mut buffer = Vec::new();

    data.chunks(256).for_each(|chunk| {
        let decrypted = key.decrypt(rsa::Pkcs1v15Encrypt, chunk).unwrap();
        buffer.extend_from_slice(&decrypted);
    });

    Ok(buffer)
}

pub fn from_file(path : String) -> Result<(RsaPrivateKey, RsaPublicKey), &'static str> {

    let f = File::open(path);

    if f.is_err() {
        return Err("Failed to open file");
    }

    let mut reader = BufReader::new(f.unwrap());
    let mut buffer = Vec::new();

    if reader.read_to_end(&mut buffer).is_err() {
        return Err("Failed to read file");
    }

    let private_key = RsaPrivateKey::from_pkcs1_der(&buffer.as_slice());

    if private_key.is_err() {
        return Err("Failed to decode private key");
    }

    let private_key = private_key.unwrap();

    let public_key = private_key.to_public_key();

    Ok((private_key, public_key))

}

pub fn to_file(path : String, key : RsaPrivateKey) -> Result<(), &'static str> {

    let f = File::create(path);

    if f.is_err() {
        return Err("Failed to create file");
    }

    let mut writer = f.unwrap();

    let encoded = key.to_pkcs1_der();

    if encoded.is_err() {
        return Err("Failed to encode private key");
    }

    let encoded = encoded.unwrap();

    if writer.write(encoded.as_bytes()).is_err() {
        return Err("Failed to write to file");
    }

    Ok(())

}

pub fn bytes_to_hex(bytes : &[u8]) -> String {
    let strs : Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}

pub fn hex_to_bytes(hex : &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..hex.len() / 2 {
        bytes.push(u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap());
    }
    bytes
}