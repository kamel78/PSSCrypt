use std::{arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128}};

use crate::aes_ciphers::{aes256::AES256 };


pub struct AesGcm256 { aes: AES256 }

impl AesGcm256 {
/// Create a new AES-GCM cipher with the given key
    pub fn new(key: &[u128]) -> Self {
                Self {aes: AES256::new(key),}
        }
    /// Encrypt and authenticate data using AES-GCM
    pub fn encrypt(&self, nonce: &[u8; 12], plaintext: &[u8], associated_data: &[u8]) -> (Vec<u8>, [u8; 16]) {
        // Step 1: Generate the hash subkey H = AES(K, 0^128)
        let h = self.aes.encrypt_block(0);
        // Step 2: Prepare the initial counter block
        let mut counter = [0u8; 16];
        counter[0..12].copy_from_slice(nonce);
        counter[15] = 1;
            // Step 3: Encrypt plaintext using CTR mode
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut counter_val = u128::from_be_bytes(counter);
        for chunk in plaintext.chunks(16) {
        let keystream = self.aes.encrypt_block(counter_val);
        let keystream_bytes = keystream.to_be_bytes();
        for (i, &byte) in chunk.iter().enumerate() {
                ciphertext.push(byte ^ keystream_bytes[i]);
                }
        counter_val = counter_val.wrapping_add(1);}
        // Step 4: Compute GHASH for authentication
        let tag = self.compute_ghash(h, associated_data, &ciphertext, nonce);
        (ciphertext, tag)
        }

    /// Decrypt and verify data using AES-GCM

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8], associated_data: &[u8], tag: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
        // Step 1: Generate the hash subkey H = AES(K, 0^128)
        let h = self.aes.encrypt_block(0);
        // Step 2: Verify the authentication tag
        let computed_tag = self.compute_ghash(h, associated_data, ciphertext, nonce);
        if !constant_time_compare(tag, &computed_tag) {return Err("Authentication failed: Invalid tag");}
        // Step 3: Decrypt ciphertext using CTR mode
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut counter = [0u8; 16];
        counter[0..12].copy_from_slice(nonce);
        counter[15] = 1;
        let mut counter_val = u128::from_be_bytes(counter);
        for chunk in ciphertext.chunks(16) {
                let keystream = self.aes.encrypt_block(counter_val);
                let keystream_bytes = keystream.to_be_bytes();
                for (i, &byte) in chunk.iter().enumerate() {plaintext.push(byte ^ keystream_bytes[i]);}
                counter_val = counter_val.wrapping_add(1);
        }
        Ok(plaintext)
        }

/// Compute GHASH for authentication
fn compute_ghash(&self, h: u128, aad: &[u8], ciphertext: &[u8], nonce: &[u8; 12]) -> [u8; 16] {
        let mut ghash_result = 0u128;
        // Process associated data
        for chunk in aad.chunks(16) {let mut block = [0u8; 16];
                                                        block[..chunk.len()].copy_from_slice(chunk);
                                                        let block_val = u128::from_be_bytes(block);
                                                        ghash_result ^= block_val;
                                                        ghash_result = gf_multiply(ghash_result, h);
                                                    }
        // Process ciphertext
        for chunk in ciphertext.chunks(16) {     let mut block = [0u8; 16];
                                                                    block[..chunk.len()].copy_from_slice(chunk);
                                                                    let block_val = u128::from_be_bytes(block);
                                                                    ghash_result ^= block_val;
                                                                    ghash_result = gf_multiply(ghash_result, h);
                                                                }
        // Process length block (AAD length || C length in bits)
        let aad_bit_len = (aad.len() as u64) * 8;
        let ct_bit_len = (ciphertext.len() as u64) * 8;
        let mut length_block = [0u8; 16];
        length_block[0..8].copy_from_slice(&aad_bit_len.to_be_bytes());
        length_block[8..16].copy_from_slice(&ct_bit_len.to_be_bytes());
        let length_val = u128::from_be_bytes(length_block);
        ghash_result ^= length_val;
        ghash_result = gf_multiply(ghash_result, h);
        // Compute final tag by encrypting GHASH result with J0
        let mut j0 = [0u8; 16];
        j0[0..12].copy_from_slice(nonce);
        j0[15] = 1;
        let j0_val = u128::from_be_bytes(j0);
        // Encrypt the counter block
        let encrypted_counter = self.aes.encrypt_block(j0_val);
        // XOR with GHASH result
        let tag = ghash_result ^ encrypted_counter;
        tag.to_be_bytes()
    }
}

pub const fn as_m128i(x: u128) -> __m128i {
    // const transmutes are stable since Rust 1.71
    unsafe { core::mem::transmute::<u128, __m128i>(x) }
}
pub const fn as_u128(x: __m128i) -> u128 {
    // const transmutes are stable since Rust 1.71
    unsafe { core::mem::transmute::<__m128i, u128>(x) }
}
pub fn gf_multiply(x: u128, y: u128) -> u128 {   
    let a = as_m128i(x);
    let b = as_m128i(y);
    unsafe {    let h0 = _mm_clmulepi64_si128(a, b, 0x00);  // a_low * b_low
                let h1 = _mm_clmulepi64_si128(a, b, 0x01);  // a_low * b_high  
                let h2 = _mm_clmulepi64_si128(a, b, 0x10);  // a_high * b_low
                let h3 = _mm_clmulepi64_si128(a, b, 0x11);  // a_high * b_high
                let h1h2 = _mm_xor_si128(h1, h2);   
                let lo = _mm_xor_si128(h0, _mm_slli_si128(h1h2, 8));
                let hi = _mm_xor_si128(h3, _mm_srli_si128(h1h2, 8));

                // Reduce a 256-bit value modulo x^128 + x^7 + x^2 + x + 1
                // The polynomial can be represented as the bit pattern 10000111 = 0x87 when we consider x^128 ≡ x^7 + x^2 + x + 1
                let poly = _mm_set_epi64x(0, 0x87);       
                let t0 = _mm_clmulepi64_si128(hi, poly, 0x00);
                let t1 = _mm_clmulepi64_si128(hi, poly, 0x01);
                let v0 = _mm_xor_si128(lo, t0);
                let v1 = _mm_xor_si128(v0, _mm_slli_si128(t1, 8));        
                let t2 = _mm_srli_si128(t1, 8);
                let t3 = _mm_clmulepi64_si128(t2, poly, 0x00);        
                as_u128(_mm_xor_si128(v1, t3))
            }
}


/// Constant-time comparison to prevent timing attacks
fn constant_time_compare(a: &[u8; 16], b: &[u8; 16]) -> bool {
let mut diff = 0u8;
for i in 0..16 {
diff |= a[i] ^ b[i];
}
diff == 0
}


