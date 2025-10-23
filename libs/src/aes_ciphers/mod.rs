
use aes::AES128;

use crate::aes_ciphers::aes256::AES256;

pub trait CipherInterface{
    type Cipher;
    fn new(key: &[u128]) -> Self::Cipher;
    fn encrypt_block(&self, input: u128) -> u128;
    fn decrypt_block(&self, input: u128) -> u128;
    fn name(&self) -> &'static str;
    fn setkey(&mut self,key: &[u128]);
}

pub mod aes;
pub mod aes256;
pub mod common_fns;

pub enum CipherName {    AES128,AES256 }

pub enum CommonCipher { AES128(AES128),AES256(AES256)  }

impl CommonCipher {
    pub fn newcipher(name: &CipherName, key: &[u128]) -> Self {
        match name {
            CipherName::AES128 => Self::AES128(AES128::new(key)),
            CipherName::AES256 => Self::AES256(AES256::new(key)),
        }
    }

    pub fn encrypt_block(&self, input: u128) -> u128 {
        match self {
            Self::AES128(c) => c.encrypt_block(input),
            Self::AES256(c) => c.encrypt_block(input),
        }
    }

    pub fn decrypt_block(&self, input: u128) -> u128 {
        match self {
            Self::AES128(c) => c.decrypt_block(input),
            Self::AES256(c) => c.decrypt_block(input),
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Self::AES128(_) => "AES128",
            Self::AES256(_) => "AES256",
        }
    }

    pub fn setkey(&mut self, key: &[u128])  {
        match self {
            Self::AES128(c) => c.setkey(key),
            Self::AES256(c) => c.setkey(key),
        }
    }
}

