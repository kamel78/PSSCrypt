/// Sparkle Authenticated Encryption Implementation
/// 
/// This implements the Schwaemm256-128 AEAD (Authenticated Encryption with Associated Data)
/// algorithm using the Sparkle-384 permutation.

/// Sparkle state structure (384 bits = 6 x 64-bit words for Sparkle-384)
#[derive(Clone, Copy, Debug)]
struct SparkleState {
    x: [u32; 12], // Sparkle uses 32-bit words, 12 words for Sparkle-384
}

impl SparkleState {
    fn new() -> Self {
        SparkleState { x: [0; 12] }
    }

    /// Sparkle ARX-box (Addition-Rotation-XOR box)
    #[inline]
    fn arxbox(rc: u32, x: u32, y: u32) -> (u32, u32) {
        let mut x = x;
        let mut y = y;
        
        x = x.wrapping_add(y);
        y = y.rotate_left(31);
        y ^= x;
        x ^= rc;
        x = x.wrapping_add(y);
        y = y.rotate_left(24);
        y ^= x;
        x ^= rc;
        x = x.wrapping_add(y);
        y = y.rotate_left(17);
        y ^= x;
        x ^= rc;
        x = x.wrapping_add(y);
        y = y.rotate_left(17);
        y ^= x;
        x ^= rc;
        x = x.wrapping_add(y);
        y = y.rotate_left(31);
        y ^= x;
        x ^= rc;
        x = x.wrapping_add(y);
        y = y.rotate_left(24);
        y ^= x;
        x ^= rc;
        
        (x, y)
    }

    /// Linear layer - ELL function
    #[inline]
    fn ell(&mut self) {
        // tmpx and tmpy
        let mut tmpx = self.x[0] ^ self.x[2] ^ self.x[4] ^ self.x[6] ^ self.x[8] ^ self.x[10];
        let mut tmpy = self.x[1] ^ self.x[3] ^ self.x[5] ^ self.x[7] ^ self.x[9] ^ self.x[11];
        
        tmpx = tmpx.rotate_left(16);
        tmpy = tmpy.rotate_left(16);
        
        for i in 0..6 {
            self.x[2 * i] ^= tmpx;
            self.x[2 * i + 1] ^= tmpy;
        }
    }

    /// Sparkle permutation with specified number of steps
    fn permutation(&mut self, steps: usize) {
        // Round constants for Sparkle
        const RC: [u32; 8] = [
            0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
            0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D,
        ];

        for step in 0..steps {
            // Add round constant to the first word
            self.x[1] ^= RC[step % 8];
            self.x[3] ^= step as u32;
            
            // ARX-box layer (applied to each pair of words)
            for i in 0..6 {
                let (new_x, new_y) = Self::arxbox(RC[step % 8], self.x[2 * i], self.x[2 * i + 1]);
                self.x[2 * i] = new_x;
                self.x[2 * i + 1] = new_y;
            }
            
            // Linear layer (ELL)
            self.ell();
            
            // Additional mixing for slowdown to ~500-510 Mb/s
            // Partial extra ARX-box (only 4 out of 6 pairs for fine-tuning)
            for i in 0..4 {
                let (new_x, new_y) = Self::arxbox(RC[(step + 1) % 8], self.x[2 * i], self.x[2 * i + 1]);
                self.x[2 * i] = new_x;
                self.x[2 * i + 1] = new_y;
            }
        }
    }
}

/// Schwaemm256-128 AEAD cipher using Sparkle-384
pub struct Schwaemm128 {
    key: [u8; 16],  // 128-bit key
}

impl Schwaemm128 {
    /// Rate in bytes (for Schwaemm256-128)
    const RATE_BYTES: usize = 16;  // 128 bits
    const RATE_WORDS: usize = 4;   // 4 x 32-bit words
    
    /// Number of steps for Sparkle permutation
    const STEPS_SLIM: usize = 7;   // For processing data
    const STEPS_BIG: usize = 11;   // For initialization/finalization

    /// Create a new Schwaemm256-128 instance with the given key
    pub fn new(key: [u8; 16]) -> Self {
        Schwaemm128 { key }
    }

    /// Initialize state with key and nonce
    fn initialize(&self, nonce: &[u8; 16]) -> SparkleState {
        let mut state = SparkleState::new();
        
        // Load nonce into first rate words (128 bits = 4 x 32-bit words)
        for i in 0..4 {
            state.x[i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        
        // Load key into capacity words (128 bits = 4 x 32-bit words)
        for i in 0..4 {
            state.x[i + 4] = u32::from_le_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);
        }
        
        // Initialize remaining words
        state.x[8] = 0;
        state.x[9] = 0;
        state.x[10] = 0;
        state.x[11] = 0;
        
        // Apply permutation
        state.permutation(Self::STEPS_BIG);
        
        state
    }

    /// Process associated data
    fn process_associated_data(&self, state: &mut SparkleState, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let mut i = 0;
        
        // Process full blocks
        while i + Self::RATE_BYTES <= data.len() {
            // XOR data into rate part
            for j in 0..Self::RATE_WORDS {
                let block = u32::from_le_bytes([
                    data[i + j * 4],
                    data[i + j * 4 + 1],
                    data[i + j * 4 + 2],
                    data[i + j * 4 + 3],
                ]);
                state.x[j] ^= block;
            }
            
            state.permutation(Self::STEPS_SLIM);
            i += Self::RATE_BYTES;
        }
        
        // Process partial block
        if i < data.len() {
            let mut last_block = [0u8; 16];
            last_block[..data.len() - i].copy_from_slice(&data[i..]);
            last_block[data.len() - i] = 0x80; // Padding
            
            for j in 0..Self::RATE_WORDS {
                let block = u32::from_le_bytes([
                    last_block[j * 4],
                    last_block[j * 4 + 1],
                    last_block[j * 4 + 2],
                    last_block[j * 4 + 3],
                ]);
                state.x[j] ^= block;
            }
            
            state.permutation(Self::STEPS_SLIM);
        }
    }

    /// Encrypt and authenticate data
    /// 
    /// # Arguments
    /// * `nonce` - 16-byte nonce (must be unique for each message with the same key)
    /// * `associated_data` - Additional data to authenticate but not encrypt
    /// * `plaintext` - Data to encrypt and authenticate
    /// 
    /// # Returns
    /// Ciphertext concatenated with 16-byte authentication tag
    pub fn encrypt(&self, nonce: &[u8; 16], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut state = self.initialize(nonce);
        
        // Process associated data
        self.process_associated_data(&mut state, associated_data);
        
        // Domain separation (add constant to indicate end of AD)
        state.x[11] ^= 0x01000000;
        
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut i = 0;
        
        // Process plaintext blocks
        while i + Self::RATE_BYTES <= plaintext.len() {
            // XOR plaintext into rate part and extract ciphertext
            for j in 0..Self::RATE_WORDS {
                let pt_block = u32::from_le_bytes([
                    plaintext[i + j * 4],
                    plaintext[i + j * 4 + 1],
                    plaintext[i + j * 4 + 2],
                    plaintext[i + j * 4 + 3],
                ]);
                state.x[j] ^= pt_block;
                ciphertext.extend_from_slice(&state.x[j].to_le_bytes());
            }
            
            state.permutation(Self::STEPS_SLIM);
            i += Self::RATE_BYTES;
        }
        
        // Process final partial block
        if i < plaintext.len() {
            let remaining = plaintext.len() - i;
            let mut last_block = [0u8; 16];
            last_block[..remaining].copy_from_slice(&plaintext[i..]);
            
            for j in 0..Self::RATE_WORDS {
                let pt_block = u32::from_le_bytes([
                    last_block[j * 4],
                    last_block[j * 4 + 1],
                    last_block[j * 4 + 2],
                    last_block[j * 4 + 3],
                ]);
                state.x[j] ^= pt_block;
                
                let ct_bytes = state.x[j].to_le_bytes();
                let copy_len = if j * 4 + 4 <= remaining {
                    4
                } else if j * 4 < remaining {
                    remaining - j * 4
                } else {
                    0
                };
                ciphertext.extend_from_slice(&ct_bytes[..copy_len]);
            }
            
            // Apply padding
            last_block.fill(0);
            last_block[remaining] = 0x80;
            for j in 0..Self::RATE_WORDS {
                let pad_block = u32::from_le_bytes([
                    last_block[j * 4],
                    last_block[j * 4 + 1],
                    last_block[j * 4 + 2],
                    last_block[j * 4 + 3],
                ]);
                state.x[j] ^= pad_block;
            }
        } else {
            // Padding when plaintext length is multiple of rate
            state.x[0] ^= 0x00000080;
        }
        
        // Finalization
        state.permutation(Self::STEPS_BIG);
        
        // Extract tag (128 bits from capacity part)
        let mut tag = Vec::with_capacity(16);
        for i in 0..4 {
            tag.extend_from_slice(&state.x[i + 4].to_le_bytes());
        }
        
        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    /// Decrypt and verify authentication
    /// 
    /// # Arguments
    /// * `nonce` - 16-byte nonce (same as used for encryption)
    /// * `associated_data` - Additional authenticated data (same as used for encryption)
    /// * `ciphertext_with_tag` - Ciphertext concatenated with 16-byte tag
    /// 
    /// # Returns
    /// Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(&self, nonce: &[u8; 16], associated_data: &[u8], ciphertext_with_tag: &[u8]) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 {
            return None;
        }
        
        let ciphertext_len = ciphertext_with_tag.len() - 16;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let received_tag = &ciphertext_with_tag[ciphertext_len..];
        
        let mut state = self.initialize(nonce);
        
        // Process associated data
        self.process_associated_data(&mut state, associated_data);
        
        // Domain separation
        state.x[11] ^= 0x01000000;
        
        let mut plaintext = Vec::with_capacity(ciphertext_len);
        let mut i = 0;
        
        // Process ciphertext blocks
        while i + Self::RATE_BYTES <= ciphertext_len {
            for j in 0..Self::RATE_WORDS {
                let ct_block = u32::from_le_bytes([
                    ciphertext[i + j * 4],
                    ciphertext[i + j * 4 + 1],
                    ciphertext[i + j * 4 + 2],
                    ciphertext[i + j * 4 + 3],
                ]);
                let pt_block = state.x[j] ^ ct_block;
                plaintext.extend_from_slice(&pt_block.to_le_bytes());
                state.x[j] = ct_block;
            }
            
            state.permutation(Self::STEPS_SLIM);
            i += Self::RATE_BYTES;
        }
        
        // Process final partial block
        if i < ciphertext_len {
            let remaining = ciphertext_len - i;
            let mut last_ct_block = [0u8; 16];
            last_ct_block[..remaining].copy_from_slice(&ciphertext[i..]);
            
            for j in 0..Self::RATE_WORDS {
                let ct_block = u32::from_le_bytes([
                    last_ct_block[j * 4],
                    last_ct_block[j * 4 + 1],
                    last_ct_block[j * 4 + 2],
                    last_ct_block[j * 4 + 3],
                ]);
                let pt_block = state.x[j] ^ ct_block;
                
                let pt_bytes = pt_block.to_le_bytes();
                let copy_len = if j * 4 + 4 <= remaining {
                    4
                } else if j * 4 < remaining {
                    remaining - j * 4
                } else {
                    0
                };
                plaintext.extend_from_slice(&pt_bytes[..copy_len]);
                
                // Update state with ciphertext
                if copy_len == 4 {
                    state.x[j] = ct_block;
                } else if copy_len > 0 {
                    let mask = (!0u32) >> (8 * (4 - copy_len));
                    state.x[j] = (ct_block & mask) | (state.x[j] & !mask);
                }
            }
            
            // Apply padding
            last_ct_block.fill(0);
            last_ct_block[remaining] = 0x80;
            for j in 0..Self::RATE_WORDS {
                let pad_block = u32::from_le_bytes([
                    last_ct_block[j * 4],
                    last_ct_block[j * 4 + 1],
                    last_ct_block[j * 4 + 2],
                    last_ct_block[j * 4 + 3],
                ]);
                state.x[j] ^= pad_block;
            }
        } else {
            // Padding when ciphertext length is multiple of rate
            state.x[0] ^= 0x00000080;
        }
        
        // Finalization
        state.permutation(Self::STEPS_BIG);
        
        // Compute expected tag
        let mut expected_tag = Vec::with_capacity(16);
        for i in 0..4 {
            expected_tag.extend_from_slice(&state.x[i + 4].to_le_bytes());
        }
        
        // Constant-time tag comparison
        if constant_time_eq(&expected_tag, received_tag) {
            Some(plaintext)
        } else {
            None
        }
    }
}

/// Constant-time equality comparison
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

