use crate::aes_ciphers::{ aes256::AES256 };

pub struct AesOcb256 {    aes: AES256}

impl AesOcb256 {
    /// Create a new AES-OCB cipher with the given key
    #[inline]
    pub fn new(key: &[u128]) -> Self {
        Self {  aes: AES256::new(key)}
    }

    /// Encrypt and authenticate data using AES-OCB
    #[inline]
    pub fn encrypt(&self,nonce: &[u8],plaintext: &[u8],associated_data: &[u8],tag_len: usize,) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        if nonce.len() > 15 {return Err("Nonce must be at most 15 bytes");}
        if tag_len > 16 {return Err("Tag length must be at most 16 bytes");}
        // Generate L values (derived from encrypting zero)
        let l_star = self.aes.encrypt_block(0);
        let l_dollar = Self::double(l_star);
        let mut l_cache = vec![l_dollar];
        
        // Pre-compute L values for efficiency
        for i in 0..32 {l_cache.push(Self::double(l_cache[i]));}

        // Process nonce to get initial offset
        let mut nonce_block = [0u8; 16];
        nonce_block[0] = ((tag_len * 8) as u8) << 4;
        nonce_block[16 - nonce.len() - 1] = 1;
        nonce_block[16 - nonce.len()..].copy_from_slice(nonce);        
        let nonce_num = u128::from_be_bytes(nonce_block);
        let bottom = (nonce_num & 0x3F) as usize;
        let top = nonce_num & !0x3Fu128;
        let ktop = self.aes.encrypt_block(top);        
        let stretch = Self::stretch(ktop, l_star);
        let offset = Self::shift_right(stretch, bottom);
        // Process plaintext
        let pt_blocks = plaintext.len() / 16;
        let pt_remainder = plaintext.len() % 16;        
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut checksum = 0u128;
        let mut offset_val = offset;
        // Process full blocks
        for i in 0..pt_blocks {  let l_i = Self::get_l(&l_cache, Self::ntz(i + 1));
                                        offset_val ^= l_i;            
                                        let pt_block = Self::bytes_to_u128(&plaintext[i * 16..(i + 1) * 16]);
                                        checksum ^= pt_block;                                        
                                        let encrypted = self.aes.encrypt_block(pt_block ^ offset_val);
                                        let ct_block = encrypted ^ offset_val;            
                                        Self::u128_to_bytes(ct_block, &mut ciphertext[i * 16..(i + 1) * 16]);
                                    }
        // Process final partial block if exists
        if pt_remainder > 0 {   offset_val ^= l_star;
                                let pad = self.aes.encrypt_block(offset_val);                                
                                let offset_bytes = pt_blocks * 16;
                                for i in 0..pt_remainder {
                                    ciphertext[offset_bytes + i] = plaintext[offset_bytes + i] ^ pad.to_be_bytes()[i];
                                }
                                // Update checksum with padded plaintext
                                let mut final_block = [0u8; 16];
                                final_block[..pt_remainder].copy_from_slice(&plaintext[offset_bytes..]);
                                final_block[pt_remainder] = 0x80;
                                checksum ^= u128::from_be_bytes(final_block);
                            }
        // Compute tag
        let tag_block = self.aes.encrypt_block(checksum ^ offset_val ^ l_dollar);       
        // Process associated data
        let auth_val = self.process_aad_ocb(associated_data, &l_cache, l_star );
        let final_tag = tag_block ^ auth_val;        
        let tag_bytes = final_tag.to_be_bytes();
        Ok((ciphertext, tag_bytes[..tag_len].to_vec()))
    }

    /// Decrypt and verify data using AES-OCB
    #[inline]
    pub fn decrypt(&self,nonce: &[u8],ciphertext: &[u8],associated_data: &[u8],tag: &[u8],) -> Result<Vec<u8>, &'static str> {
        if nonce.len() > 15 {return Err("Nonce must be at most 15 bytes");}
        if tag.len() > 16 {return Err("Invalid tag length");}
        let tag_len = tag.len();
        // Generate L values
        let l_star = self.aes.encrypt_block(0);
        let l_dollar = Self::double(l_star);
        let mut l_cache = vec![l_dollar];        
        for i in 0..32 {l_cache.push(Self::double(l_cache[i]));}
        // Process nonce
        let mut nonce_block = [0u8; 16];
        nonce_block[0] = ((tag_len * 8) as u8) << 4;
        nonce_block[16 - nonce.len() - 1] = 1;
        nonce_block[16 - nonce.len()..].copy_from_slice(nonce);        
        let nonce_num = u128::from_be_bytes(nonce_block);
        let bottom = (nonce_num & 0x3F) as usize;
        let top = nonce_num & !0x3Fu128;
        let ktop = self.aes.encrypt_block(top);        
        let stretch = Self::stretch(ktop, l_star);
        let offset = Self::shift_right(stretch, bottom);
        // Process ciphertext
        let ct_blocks = ciphertext.len() / 16;
        let ct_remainder = ciphertext.len() % 16;        
        let mut plaintext = vec![0u8; ciphertext.len()];
        let mut checksum = 0u128;
        let mut offset_val = offset;
        // Process full blocks
        for i in 0..ct_blocks {  let l_i = Self::get_l(&l_cache, Self::ntz(i + 1));
                                        offset_val ^= l_i;                                        
                                        let ct_block = Self::bytes_to_u128(&ciphertext[i * 16..(i + 1) * 16]);
                                        let decrypted = self.aes.decrypt_block(ct_block ^ offset_val); 
                                        let pt_block = decrypted ^ offset_val;                                        
                                        checksum ^= pt_block;
                                        Self::u128_to_bytes(pt_block, &mut plaintext[i * 16..(i + 1) * 16]);
                                    }
        // Process final partial block
        if ct_remainder > 0 {   offset_val ^= l_star;
                                let pad = self.aes.encrypt_block(offset_val);                                
                                let offset_bytes = ct_blocks * 16;
                                for i in 0..ct_remainder {  plaintext[offset_bytes + i] = ciphertext[offset_bytes + i] ^ pad.to_be_bytes()[i];}                                
                                // Update checksum
                                let mut final_block = [0u8; 16];
                                final_block[..ct_remainder].copy_from_slice(&plaintext[offset_bytes..]);
                                final_block[ct_remainder] = 0x80;
                                checksum ^= u128::from_be_bytes(final_block);
                            }
        // Verify tag
        let tag_block = self.aes.encrypt_block(checksum ^ offset_val ^ l_dollar);
        let auth_val = self.process_aad_ocb(associated_data, &l_cache, l_star );
        let expected_tag = tag_block ^ auth_val;        
        let expected_tag_bytes = expected_tag.to_be_bytes();
        if !constant_time_compare(tag, &expected_tag_bytes[..tag_len]) {
                                plaintext.zeroize();
                                return Err("Authentication failed: Invalid tag");
                            }
        Ok(plaintext)
    }

    /// Process associated data for OCB
    #[inline]
    fn process_aad_ocb(&self, aad: &[u8], l_cache: &[u128], l_star: u128 ) -> u128 {
        if aad.is_empty() {return 0;}
        let blocks = aad.len() / 16;
        let remainder = aad.len() % 16;        
        let mut offset_val = 0u128;
        let mut sum = 0u128;
        // Process full blocks
        for i in 0..blocks {    let l_i = Self::get_l(l_cache, Self::ntz(i + 1));
                                        offset_val ^= l_i;                                        
                                        let block = Self::bytes_to_u128(&aad[i * 16..(i + 1) * 16]);
                                        sum ^= self.aes.encrypt_block(block ^ offset_val);
                                    }
        // Process final partial block
        if remainder > 0 {  offset_val ^= l_star;            
                            let mut final_block = [0u8; 16];
                            final_block[..remainder].copy_from_slice(&aad[blocks * 16..]);
                            final_block[remainder] = 0x80;                            
                            let block_val = u128::from_be_bytes(final_block);
                            sum ^= self.aes.encrypt_block(block_val ^ offset_val);
                        }
        sum
    }

    // Helper functions for OCB
    #[inline]
    fn double(x: u128) -> u128 {
        let msb = (x >> 127) & 1;
        let shifted = x << 1;
        shifted ^ (msb * 0x87)
    }

    #[inline]
    fn stretch(ktop: u128, l_star: u128) -> [u128; 2] {
        let xor_val = ktop ^ (l_star >> 8);
        [ktop, xor_val]
    }

    #[inline]
    fn shift_right(stretch: [u128; 2], amount: usize) -> u128 {
        if amount == 0 {
            stretch[0]
        } else if amount < 128 {
            (stretch[0] >> amount) | (stretch[1] << (128 - amount))
        } else {
            stretch[1] >> (amount - 128)
        }
    }

    #[inline]
    fn ntz(x: usize) -> usize {
        x.trailing_zeros() as usize
    }

    #[inline]
    fn get_l(l_cache: &[u128], i: usize) -> u128 {
        l_cache[i]
    }

    #[inline]
    fn bytes_to_u128(bytes: &[u8]) -> u128 {
        u128::from_be_bytes(bytes.try_into().unwrap())
    }

    #[inline]
    fn u128_to_bytes(val: u128, bytes: &mut [u8]) {
        bytes.copy_from_slice(&val.to_be_bytes());
    }
}

/// Constant-time comparison
#[inline]
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }    
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for Vec<u8> {
    #[inline]
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

