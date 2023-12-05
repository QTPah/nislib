use palserializer::*;
use rsa::{RsaPublicKey, RsaPrivateKey};
use rsa::pkcs1::DecodeRsaPublicKey;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

use crate::srsa;

#[derive(Clone, Copy, EnumIter)]
pub enum PacketType {
    // Connection Types
    RRequest, // Riddle Request
    RResponse, // Riddle Response
    CReport, // Completion Report
    Validation, // Validation

    Error, // Error
    GetFallback,

    Message
}

#[derive(Clone)]
pub struct Packet { // TODO: Add signature
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
    pub encrypted: bool,
    pub source: Vec<u8>,
    pub destination: Vec<u8>,
}

impl Packet {
    pub fn new(packet_type: PacketType, payload: Vec<u8>, source: Vec<u8>, destination: Vec<u8>) -> Packet {
        Packet {
            packet_type,
            payload,
            encrypted: false,
            source,
            destination
        }
    }

    pub fn encrypt(&mut self, public_key: Option<RsaPublicKey>) -> Packet {
        if !self.encrypted {
            self.payload = srsa::encrypt(public_key.unwrap_or_else(|| RsaPublicKey::from_pkcs1_der(self.destination.clone().as_slice()).unwrap()), self.payload.clone()).unwrap();
            self.encrypted = true;
        }

        self.clone()
    }

    pub fn decrypt(mut self, private_key: RsaPrivateKey) -> Packet {
        if self.encrypted {
            self.payload = srsa::decrypt(private_key, self.payload.clone()).unwrap();
            self.encrypted = false;
        }
        
        self.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer: Vec<Vec<u8>> = Vec::new();
    
        let packet_type = self.packet_type as u8;
        buffer.push(vec![packet_type]);
        buffer.push(self.payload.clone());
        let encrypted = if self.encrypted { 1 } else { 0 };
        buffer.push(vec![encrypted]);
        buffer.push(self.source.to_vec());
        buffer.push(self.destination.to_vec());
    
        serialize_be(&buffer.iter().map(|x| &x[..]).collect::<Vec<_>>()).unwrap()
    }

    pub fn from_bytes(data: &[u8]) -> Packet {
        let data = deserialize_be(data).unwrap();

        let packet_type: PacketType = PacketType::iter().nth(data[0][0] as usize).unwrap();
        let payload = data[1].to_vec();
        let encrypted = data[2][0] == 1;
        let source = data[3].to_vec();
        let destination = data[4].to_vec();

        Packet {
            packet_type,
            payload,
            source,
            destination,
            encrypted
        }
    }
}