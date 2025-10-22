use crate::{aes_ciphers::{CipherName, CommonCipher},pss::params::* };
use rand::Rng;
use std::{arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_set_epi64x, _mm_slli_si128, _mm_srli_si128, _mm_xor_si128}, ptr};

const W_SIZE :usize = 4;
pub struct PSSCrypt {
    pub internal: Vec<__m128i>, 
    pub prp: CommonCipher,
    pub prp_name :CipherName,
    key : [u128;2],
    iv : u128,
    authenticate : bool
}

// Multiply two 128-bit field elements in GF(2^128) #[target_feature(enable = "pclmulqdq")]
#[inline(always)] 
pub fn gf_mul(a: __m128i, b: __m128i) -> __m128i {   
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
                _mm_xor_si128(v1, t3)
            }
}
 
// Add two Gf128 element 
#[inline(always)] 
pub fn gf_add(a: __m128i, b: __m128i) -> __m128i    
        {                            
            unsafe {_mm_xor_si128(a ,b)}
        }

//  Implementation of the proposed PSS based encryption/decryption scheme
impl PSSCrypt {
    pub fn new(bytes: &[u8],in_length :usize, prp_name :CipherName, authenticate :bool) -> Self {                
        let length = if in_length == 0 {bytes.len()} else {in_length};
        if length < 64 {panic!("Minimum data size that cn be encrypted with the PSS with windows size w=4 is 64byte (4 blocks of 128bit each) !")}
        let mut internal = Vec::<__m128i>::new();
        let blocks_count = (length / 16) + 1;  // Alwayse add  1 for the padding          
        internal.reserve(blocks_count + 1); // reserver a place for the Tag
        unsafe {       ptr::copy_nonoverlapping(
                                bytes.as_ptr(),
                                internal.as_mut_ptr().add(1) as *mut u8,
                                length - (length %16)
                                );
                        internal.set_len(blocks_count+1);
                }                 
        let last_block: __m128i;     
        if length % 16 == 0  {last_block = unsafe { core::mem::transmute::<[u8; 16], __m128i>([16u8;16]) }  }                 
        else {  // Implements padding scheme PCSK#1
                let pad_size= 16 - length % 16;
                let mut pad =[0u8;16];
                for i in 0..16 {    if i>=16-pad_size {pad[i] = pad_size as u8}
                                            else {pad[i] = bytes[(blocks_count-1)*16+i] as u8} 
                                        }                                
                last_block =  unsafe {core::mem::transmute::<[u8; 16], __m128i>(pad)  }
                }
        internal[blocks_count] = last_block;                    
        let key1 = rand::rng().random::<u128>();
        let key2 = rand::rng().random::<u128>();             
        let iv = rand::rng().random::<u128>();             
        let prp_cipher = CommonCipher::newcipher(&prp_name, &[key1,key2]);  
        PSSCrypt {  internal ,  prp: prp_cipher ,prp_name, key: [key1,key2], iv , authenticate }
    }
    
    pub fn encrypted_bytes(&self) -> &[u8] {
        unsafe {    std::slice::from_raw_parts(
                    self.internal.as_ptr() as *const u8,
                    self.internal.len() * 16
                    )
                }
    }

    pub fn decrypted_bytes(&self) -> &[u8] {
        unsafe {    std::slice::from_raw_parts(
                    self.internal.as_ptr().add(1) as *const u8,
                    (self.internal.len()-1) * 16 - (as_u128(self.internal[self.internal.len()-1])>>120) as usize
                    )
                }
    }

    pub fn set_key_materials(&mut self, key :&[u128;2], iv:u128, prp_name :CipherName){
        self.prp = CommonCipher::newcipher(&prp_name, key);
        self.key = *key;
        self.iv =iv;
        self.prp_name = prp_name;
    }
    // PSS Encryption : optimized version
    #[inline]
    pub fn encrypt(&mut self) -> u128 {
        let len = self.internal.len() - 1;   
        // Branchless decomposition
        let (mut l, mut r) = (len / W_SIZE, len % W_SIZE);
        let needs_adjust = (r == 0) as usize;
        l = l.wrapping_sub(needs_adjust);
        r = r + needs_adjust * W_SIZE;
            // Stack allocation for better cache locality
        let mut f: [__m128i; 2 * W_SIZE] = [M128IZERO; 2 * W_SIZE];
        let mut tmp: [__m128i; W_SIZE + 1] = [M128IZERO; W_SIZE + 1];   
        // Encrypt IV once
        self.prp.setkey(&self.key);
        self.internal[0] = as_m128i(self.prp.encrypt_block(self.iv));    
        // === FIRST PSS: PSS(5),1,5,4 - Loop Unrolling ===
        #[allow(clippy::needless_range_loop)]
        for i in 0..=W_SIZE {
            let mut acc = M128IZERO;
            let m1_row = &M1[i];        
            // Unroll by 4 if W_SIZE+1 is divisible by 4
            let mut j = 0;
            while j + 3 < W_SIZE + 1 {
                acc = gf_add(acc, gf_mul(m1_row[j], self.internal[j]));
                acc = gf_add(acc, gf_mul(m1_row[j+1], self.internal[j+1]));
                acc = gf_add(acc, gf_mul(m1_row[j+2], self.internal[j+2]));
                acc = gf_add(acc, gf_mul(m1_row[j+3], self.internal[j+3]));
                j += 4;
            }        
            // Handle remainder
            while j <= W_SIZE {
                acc = gf_add(acc, gf_mul(m1_row[j], self.internal[j]));
                j += 1;
            }        
            tmp[i] = acc;
        }
        self.internal[0] = tmp[W_SIZE];    
        // === SECOND PSS: PSS(8),4,8,4 - Optimized iteration ===
        for i in 1..l {
            let idx = i * W_SIZE + 1;
            let id = (i - 1) * W_SIZE + 1;        
            // Batch copy operations
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.internal.as_ptr().add(idx),
                    f.as_mut_ptr().add(W_SIZE),
                    W_SIZE
                );
                std::ptr::copy_nonoverlapping(
                    tmp.as_ptr(),
                    f.as_mut_ptr(),
                    W_SIZE
                );
            }        
            // Compute with blocking for better cache usage
            const BLOCK_SIZE: usize = 4;        
            for a in 0..W_SIZE {
                let m_row_upper = &M[3][a + 4];
                let m_row_lower = &M[3][a];            
                let mut acc1 = M128IZERO;
                let mut acc2 = M128IZERO;            
                // Process in blocks
                let mut b = 0;
                while b + BLOCK_SIZE - 1 < 2 * W_SIZE {
                    // Unroll block
                    for offset in 0..BLOCK_SIZE {
                        let f_val = f[b + offset];
                        acc1 = gf_add(acc1, gf_mul(m_row_upper[b + offset], f_val));
                        acc2 = gf_add(acc2, gf_mul(m_row_lower[b + offset], f_val));
                    }
                    b += BLOCK_SIZE;
                }            
                // Remainder
                while b < 2 * W_SIZE {
                    let f_val = f[b];
                    acc1 = gf_add(acc1, gf_mul(m_row_upper[b], f_val));
                    acc2 = gf_add(acc2, gf_mul(m_row_lower[b], f_val));
                    b += 1;
                }            
                self.internal[id + a] = acc1;
                tmp[a] = acc2;
            }
        }    
        // Prepare for final PSS
        unsafe {
            std::ptr::copy_nonoverlapping(tmp.as_ptr(), f.as_mut_ptr(), W_SIZE);
        }    
        let last_block_start = l * W_SIZE + 1;
        if r > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.internal.as_ptr().add(last_block_start),
                    f.as_mut_ptr().add(W_SIZE),
                    r
                );
            }
        }    
        // === THIRD PSS: PSS(4+r),r,4+r,r ===
        let id = (l - 1) * W_SIZE + 1;
        let matrix_size = W_SIZE + r;
        let m_final = &M[r - 1];    
        // Compute self.internal updates with loop unrolling
        for i in 0..r {
            let m_row = &m_final[W_SIZE + i];
            let mut acc = M128IZERO;        
            let mut j = 0;
            while j + 3 < matrix_size {
                acc = gf_add(acc, gf_mul(m_row[j], f[j]));
                acc = gf_add(acc, gf_mul(m_row[j+1], f[j+1]));
                acc = gf_add(acc, gf_mul(m_row[j+2], f[j+2]));
                acc = gf_add(acc, gf_mul(m_row[j+3], f[j+3]));
                j += 4;
            }        
            while j < matrix_size {
                acc = gf_add(acc, gf_mul(m_row[j], f[j]));
                j += 1;
            }        
            self.internal[id + i] = acc;
        }    
        // Compute tmp updates with loop unrolling
        for i in 0..W_SIZE {
            let m_row = &m_final[i];
            let mut acc = M128IZERO;        
            let mut j = 0;
            while j + 3 < matrix_size {
                acc = gf_add(acc, gf_mul(m_row[j], f[j]));
                acc = gf_add(acc, gf_mul(m_row[j+1], f[j+1]));
                acc = gf_add(acc, gf_mul(m_row[j+2], f[j+2]));
                acc = gf_add(acc, gf_mul(m_row[j+3], f[j+3]));
                j += 4;
            }        
            while j < matrix_size {
                acc = gf_add(acc, gf_mul(m_row[j], f[j]));
                j += 1;
            }        
            tmp[i] = acc;
        }    
        // === CBC encryption - Pipeline optimization ===
        let mut tiv = self.internal[0];
        let output_start = id + r;    
        for i in 0..W_SIZE {
            let xored = gf_add(tiv, tmp[i]);
            let encrypted = self.prp.encrypt_block(as_u128(xored));
            let result = as_m128i(encrypted);
            self.internal[output_start + i] = result;
            tiv = result;
        }    
        // Branchless authentication
        let auth_mask = -(self.authenticate as i128) as u128;
        let key1 = self.prp.encrypt_block(1u128);
        let key2 = self.prp.encrypt_block(2u128);
        self.prp.setkey(&[key1,key2]);
        let auth_result = self.prp.encrypt_block(self.iv);    
        auth_result & auth_mask
    }

    // PSS Deccryption : optimized version
    #[inline]
    pub fn decrypt(&mut self, check_tag: u128, silent :bool) -> u128{
        let len = self.internal.len() - 1;   
        // Branchless decomposition
        let (mut l, mut r) = (len / W_SIZE, len % W_SIZE);
        let needs_adjust = (r == 0) as usize;
        l = l.wrapping_sub(needs_adjust);
        r = r + needs_adjust * W_SIZE;    
        // Stack allocation
        let mut f: [__m128i; 2 * W_SIZE] = [M128IZERO; 2 * W_SIZE];
        let mut tmp: [__m128i; W_SIZE + 1] = [M128IZERO; W_SIZE + 1];    
        self.prp.setkey(&self.key);    
        // === CBC DECRYPTION - Optimized ===
        let last = ((l - 1) * W_SIZE) + 1 + r;
        let mut tiv = self.internal[0];    
        // Unroll CBC decryption
        for i in 0..W_SIZE {
            let decrypted = self.prp.decrypt_block(as_u128(self.internal[last + i]));
            f[i] = gf_add(as_m128i(decrypted), tiv);
            tiv = self.internal[last + i];
        }    
        // Batch copy for f array
        if r > 0 {
            let src_start = last - r;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.internal.as_ptr().add(src_start),
                    f.as_mut_ptr().add(W_SIZE),
                    r
                );
            }
        }    
        // === THIRD PSS RECONSTRUCTION: PSS(4+r),r,4+r,r ===
        let id = l * W_SIZE + 1;
        let matrix_size = W_SIZE + r;
        let d_final = &D[r - 1];    
        // Compute self.internal updates with unrolling
        for i in 0..r {
            let d_row = &d_final[W_SIZE + i];
            let mut acc = M128IZERO;        
            let mut j = 0;
            while j + 3 < matrix_size {
                acc = gf_add(acc, gf_mul(d_row[j], f[j]));
                acc = gf_add(acc, gf_mul(d_row[j+1], f[j+1]));
                acc = gf_add(acc, gf_mul(d_row[j+2], f[j+2]));
                acc = gf_add(acc, gf_mul(d_row[j+3], f[j+3]));
                j += 4;
            }        
            while j < matrix_size {
                acc = gf_add(acc, gf_mul(d_row[j], f[j]));
                j += 1;
            }        
            self.internal[id + i] = acc;
        }    
        // Compute tmp updates with unrolling
        for i in 0..W_SIZE {
            let d_row = &d_final[i];
            let mut acc = M128IZERO;        
            let mut j = 0;
            while j + 3 < matrix_size {
                acc = gf_add(acc, gf_mul(d_row[j], f[j]));
                acc = gf_add(acc, gf_mul(d_row[j+1], f[j+1]));
                acc = gf_add(acc, gf_mul(d_row[j+2], f[j+2]));
                acc = gf_add(acc, gf_mul(d_row[j+3], f[j+3]));
                j += 4;
            }        
            while j < matrix_size {
                acc = gf_add(acc, gf_mul(d_row[j], f[j]));
                j += 1;
            }        
            tmp[i] = acc;
        }
        
        // === SECOND PSS RECONSTRUCTION: PSS(8),4,8,4 - Reverse iteration ===
        for i in (1..l).rev() {
            let idx = (i - 1) * W_SIZE + 1;
            let id = i * W_SIZE + 1;        
            // Batch copy with unsafe for performance
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.internal.as_ptr().add(idx),
                    f.as_mut_ptr().add(W_SIZE),
                    W_SIZE
                );
                std::ptr::copy_nonoverlapping(
                    tmp.as_ptr(),
                    f.as_mut_ptr(),
                    W_SIZE
                );
            }        
            // Cache-blocked computation
            const BLOCK_SIZE: usize = 4;        
            for a in 0..W_SIZE {
                let d_row_upper = &D[3][a + 4];
                let d_row_lower = &D[3][a];            
                let mut acc1 = M128IZERO;
                let mut acc2 = M128IZERO;            
                // Process in blocks
                let mut b = 0;
                while b + BLOCK_SIZE - 1 < 2 * W_SIZE {
                    for offset in 0..BLOCK_SIZE {
                        let f_val = f[b + offset];
                        acc1 = gf_add(acc1, gf_mul(d_row_upper[b + offset], f_val));
                        acc2 = gf_add(acc2, gf_mul(d_row_lower[b + offset], f_val));
                    }
                    b += BLOCK_SIZE;
                }            
                // Remainder
                while b < 2 * W_SIZE {
                    let f_val = f[b];
                    acc1 = gf_add(acc1, gf_mul(d_row_upper[b], f_val));
                    acc2 = gf_add(acc2, gf_mul(d_row_lower[b], f_val));
                    b += 1;
                }            
                self.internal[id + a] = acc1;
                tmp[a] = acc2;
            }
        }
        
        // === FIRST PSS RECONSTRUCTION: PSS(5),1,5,4 ===
        tmp[W_SIZE] = self.internal[0];    
        #[allow(clippy::needless_range_loop)]
        for i in 0..=W_SIZE {
            let d1_row = &D1[i];
            let mut acc = M128IZERO;        
            // Unroll by 4
            let mut j = 0;
            while j + 3 < W_SIZE + 1 {
                acc = gf_add(acc, gf_mul(d1_row[j], tmp[j]));
                acc = gf_add(acc, gf_mul(d1_row[j+1], tmp[j+1]));
                acc = gf_add(acc, gf_mul(d1_row[j+2], tmp[j+2]));
                acc = gf_add(acc, gf_mul(d1_row[j+3], tmp[j+3]));
                j += 4;
            }        
            while j <= W_SIZE {
                acc = gf_add(acc, gf_mul(d1_row[j], tmp[j]));
                j += 1;
            }        
            self.internal[i] = acc;
        }    
        // === AUTHENTICATION - Constant-time ===
        if self.authenticate {
            let recovered_iv = self.prp.decrypt_block(as_u128(self.internal[0]));
            let key1 = self.prp.encrypt_block(1u128);
            let key2 = self.prp.encrypt_block(2u128);
            self.prp.setkey(&[key1,key2]);
            let decoded_iv = self.prp.decrypt_block(check_tag);        
            // Constant-time comparison
            let is_valid = decoded_iv == recovered_iv;        
            if !is_valid & !silent {
                // Clear sensitive data before panicking
                self.internal.fill(M128IZERO);
                panic!("Invalid ciphertext, possibly tampered!");
            }
            recovered_iv
        }
        else {0}
    }

}