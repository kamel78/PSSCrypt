use crate::aes_ciphers::{aes256::AES256 };

pub struct AesCcm256 { aes: AES256 }

impl AesCcm256 {
    /// Create a new AES-CCM cipher with the given key
    #[inline]
    pub fn new(key: &[u128]) -> Self {
        Self { aes: AES256::new(key) }
    }
    /// Encrypt and authenticate data using AES-CCM
    #[inline]
    pub fn encrypt(&self,nonce: &[u8],plaintext: &[u8],associated_data: &[u8],tag_len: usize,) -> Result<(Vec<u8>, Vec<u8>), &'static str> {        
        if nonce.len() < 7 || nonce.len() > 13 {return Err("Nonce must be 7-13 bytes");}
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag_len) {return Err("Tag length must be 4, 6, 8, 10, 12, 14, or 16 bytes");}        
        let q = 15 - nonce.len();        
        let mut ciphertext = vec![0u8; plaintext.len()];        
        // Step 1: Compute authentication tag using CBC-MAC
        let tag = self.compute_cbc_mac(nonce, plaintext, associated_data, tag_len, q)?;        
        // Step 2: Encrypt plaintext using CTR mode (in-place into pre-allocated buffer)
        self.ctr_mode_fast(nonce, plaintext, &mut ciphertext, q);        
        // Step 3: Encrypt the MAC tag using CTR mode with counter 0
        let encrypted_tag = self.encrypt_tag(&tag, nonce, q);        
        Ok((ciphertext, encrypted_tag))
    }

    /// Decrypt and verify data using AES-CCM
    #[inline]
    pub fn decrypt(&self,nonce: &[u8],ciphertext: &[u8],associated_data: &[u8],tag: &[u8],) -> Result<Vec<u8>, &'static str> {
        if nonce.len() < 7 || nonce.len() > 13 {return Err("Nonce must be 7-13 bytes");}
        if ![4, 6, 8, 10, 12, 14, 16].contains(&tag.len()) {return Err("Invalid tag length");}        
        let q = 15 - nonce.len();        
        let mut plaintext = vec![0u8; ciphertext.len()];        
        // Step 1: Decrypt the ciphertext using CTR mode
        self.ctr_mode_fast(nonce, ciphertext, &mut plaintext, q);        
        // Step 2: Compute the expected MAC tag
        let expected_tag = self.compute_cbc_mac(nonce, &plaintext, associated_data, tag.len(), q)?;        
        // Step 3: Encrypt the computed tag
        let encrypted_expected_tag = self.encrypt_tag(&expected_tag, nonce, q);        
        // Step 4: Verify the tag (constant-time)
        if !constant_time_compare(tag, &encrypted_expected_tag) {// Clear plaintext before returning error
                                                                        plaintext.zeroize();
                                                                        return Err("Authentication failed: Invalid tag");
                                                                    }        
        Ok(plaintext)
    }

    /// Compute CBC-MAC for authentication (optimized)
    #[inline]
    fn compute_cbc_mac(&self,nonce: &[u8],plaintext: &[u8],associated_data: &[u8],tag_len: usize,q: usize,) -> Result<Vec<u8>, &'static str> {
        // Build the first block B_0
        let mut b0 = [0u8; 16];        
        // Flags byte
        let has_aad = (!associated_data.is_empty()) as u8;
        let m = ((tag_len - 2) / 2) as u8;
        let l = (q - 1) as u8;
        b0[0] = (has_aad << 6) | (m << 3) | l;        
        // Nonce - use unsafe copy for speed
        let nonce_len = nonce.len();
        unsafe {std::ptr::copy_nonoverlapping(
                nonce.as_ptr(),
                b0.as_mut_ptr().add(1),
                nonce_len,
            );
        }        
        // Message length (Q bytes)
        let msg_len = plaintext.len();
        let q_bytes = msg_len.to_be_bytes();
        let start = 16 - q;
        b0[start..].copy_from_slice(&q_bytes[8 - q..]);        
        // Initialize CBC-MAC
        let mut mac_state = u128::from_be_bytes(b0);
        mac_state = self.aes.encrypt_block(mac_state);        
        // Process AAD if present
        if has_aad != 0 {mac_state = self.process_aad_fast(mac_state, associated_data);}        
        // Process plaintext in optimized chunks
        mac_state = self.process_plaintext_fast(mac_state, plaintext);        
        // Extract tag
        let mac_bytes = mac_state.to_be_bytes();
        Ok(mac_bytes[..tag_len].to_vec())
    }

    /// Process plaintext for CBC-MAC 
    #[inline]
    fn process_plaintext_fast(&self, mut mac_state: u128, plaintext: &[u8]) -> u128 {
        let len = plaintext.len();
        let full_blocks = len / 16;
        let remainder = len % 16;        
        for i in 0..full_blocks {    let offset = i * 16;
                                            let block_bytes = &plaintext[offset..offset + 16];            
                                            let block_val = unsafe {
                                                std::ptr::read_unaligned(block_bytes.as_ptr() as *const u128).to_be()
                                            };            
            mac_state ^= block_val;
            mac_state = self.aes.encrypt_block(mac_state);
        }        
        // Process remainder if exists
        if remainder > 0 {  let mut block = [0u8; 16];
                            let offset = full_blocks * 16;
                            unsafe {
                                std::ptr::copy_nonoverlapping(
                                    plaintext.as_ptr().add(offset),
                                    block.as_mut_ptr(),
                                    remainder,
                                );
                            }            
                            let block_val = u128::from_be_bytes(block);
                            mac_state ^= block_val;
                            mac_state = self.aes.encrypt_block(mac_state);
                        }        
        mac_state
    }

    /// Process Additional Authenticated Data for CBC-MAC 
    #[inline]
    fn process_aad_fast(&self, mut mac_state: u128, aad: &[u8]) -> u128 {
        let aad_len = aad.len();        
        // Calculate total AAD block size
        let header_len = if aad_len < 0xFF00 { 2 } else { 10 };
        let total_len = header_len + aad_len;
        let padded_len = (total_len + 15) & !15; 
        // Pre-allocate with exact size
        let mut aad_block = vec![0u8; padded_len];        
        // Encode AAD length
        if aad_len < 0xFF00 {   aad_block[0..2].copy_from_slice(&(aad_len as u16).to_be_bytes());} 
        else {  aad_block[0..2].copy_from_slice(&[0xFF, 0xFE]);
                aad_block[2..10].copy_from_slice(&(aad_len as u64).to_be_bytes());
                }        
        aad_block[header_len..header_len + aad_len].copy_from_slice(aad);        
        // Process AAD blocks (unrolled)
        let num_blocks = padded_len / 16;
        for i in 0..num_blocks {    let offset = i * 16;            
            let block_val = unsafe {    std::ptr::read_unaligned(aad_block.as_ptr().add(offset) as *const u128).to_be()
                                            };            
            mac_state ^= block_val;
            mac_state = self.aes.encrypt_block(mac_state);
        }        
        mac_state
    }

    /// CTR mode encryption/decryption (optimized in-place version)
    #[inline]
    fn ctr_mode_fast(&self, nonce: &[u8], input: &[u8], output: &mut [u8], q: usize) {
        let nonce_len = nonce.len();
        let num_blocks = (input.len() + 15) / 16;        
        // Build base counter block (reused for all iterations)
        let mut ctr_block = [0u8; 16];
        ctr_block[0] = (q - 1) as u8;
        unsafe {    std::ptr::copy_nonoverlapping(nonce.as_ptr(),ctr_block.as_mut_ptr().add(1),nonce_len,);}        
        let counter_start = 16 - q;        
        for block_idx in 0..num_blocks {    // Update counter (starts at 1 for data)
                                                    let counter = (block_idx + 1) as u64;
                                                    let counter_bytes = counter.to_be_bytes();
                                                    ctr_block[counter_start..].copy_from_slice(&counter_bytes[8 - q..]);                                                    
                                                    // Encrypt counter block
                                                    let ctr_val = u128::from_be_bytes(ctr_block);
                                                    let keystream = self.aes.encrypt_block(ctr_val);
                                                    let keystream_bytes = keystream.to_be_bytes();                                                    
                                                    // XOR with input (handle last partial block)
                                                    let offset = block_idx * 16;
                                                    let chunk_len = (input.len() - offset).min(16);                                                    
                                                    for i in 0..chunk_len {output[offset + i] = input[offset + i] ^ keystream_bytes[i];}
                                                }
    }
    /// Encrypt the MAC tag with counter 0 (optimized)
    #[inline]
    fn encrypt_tag(&self, tag: &[u8], nonce: &[u8], q: usize) -> Vec<u8> {
        let mut ctr_block = [0u8; 16];
        ctr_block[0] = (q - 1) as u8;        
        let nonce_len = nonce.len();
        unsafe {std::ptr::copy_nonoverlapping(nonce.as_ptr(),ctr_block.as_mut_ptr().add(1),nonce_len,);}        
        // Counter is 0 for tag encryption (already zero in ctr_block)
        let ctr_val = u128::from_be_bytes(ctr_block);
        let keystream = self.aes.encrypt_block(ctr_val);
        let keystream_bytes = keystream.to_be_bytes();        
        let tag_len = tag.len();
        let mut encrypted_tag = vec![0u8; tag_len];        
        // Unrolled XOR (most tags are 16 bytes)
        if tag_len == 16 {  for i in 0..16 {    encrypted_tag[i] = tag[i] ^ keystream_bytes[i];}
        } 
        else {    for i in 0..tag_len {encrypted_tag[i] = tag[i] ^ keystream_bytes[i];}}        
        encrypted_tag
    }
}

/// Constant-time comparison to prevent timing attacks 
#[inline]
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {return false;}    
    let mut diff = 0u8;
    let len = a.len();    
    // Unroll by 8 for better performance
    let mut i = 0;
    while i + 7 < len { diff |= a[i] ^ b[i];
                        diff |= a[i + 1] ^ b[i + 1];
                        diff |= a[i + 2] ^ b[i + 2];
                        diff |= a[i + 3] ^ b[i + 3];
                        diff |= a[i + 4] ^ b[i + 4];
                        diff |= a[i + 5] ^ b[i + 5];
                        diff |= a[i + 6] ^ b[i + 6];
                        diff |= a[i + 7] ^ b[i + 7];
                        i += 8;
                    }    
    // Handle remainder
    while i < len {diff |= a[i] ^ b[i];i += 1;}    
    diff == 0
}

// Extension trait for zeroing memory
trait Zeroize {fn zeroize(&mut self);}

impl Zeroize for Vec<u8> {
    #[inline]
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            unsafe {std::ptr::write_volatile(byte, 0);}
        }
    }
}

