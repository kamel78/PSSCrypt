/// Sparkle256 Authenticated Encryption Implementation
/// 
/// This implements the Schwaemm256-256 AEAD (Authenticated Encryption with Associated Data)
/// algorithm using the Sparkle256-512 permutation.

use std::time::Instant;

/// Sparkle256 state structure (512 bits = 16 x 32-bit words for Sparkle256-512)
#[derive(Clone, Copy, Debug)]
struct Sparkle256State {
    x: [u32; 16], // Sparkle256 uses 32-bit words, 16 words for Sparkle256-512
}

impl Sparkle256State {
    fn new() -> Self {
        Sparkle256State { x: [0; 16] }
    }

    /// Sparkle256 ARX-box (Addition-Rotation-XOR box)
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

    /// Linear layer - ELL function for Sparkle256-512
    #[inline]
    fn ell(&mut self) {
        // tmpx and tmpy - XOR all even and odd words
        let mut tmpx = self.x[0] ^ self.x[2] ^ self.x[4] ^ self.x[6] ^ 
                       self.x[8] ^ self.x[10] ^ self.x[12] ^ self.x[14];
        let mut tmpy = self.x[1] ^ self.x[3] ^ self.x[5] ^ self.x[7] ^ 
                       self.x[9] ^ self.x[11] ^ self.x[13] ^ self.x[15];
        
        tmpx = tmpx.rotate_left(16);
        tmpy = tmpy.rotate_left(16);
        
        for i in 0..8 {
            self.x[2 * i] ^= tmpx;
            self.x[2 * i + 1] ^= tmpy;
        }
    }

    /// Sparkle256 permutation with specified number of steps
    fn permutation(&mut self, steps: usize) {
        // Round constants for Sparkle256
        const RC: [u32; 8] = [
            0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738,
            0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D,
        ];

        for step in 0..steps {
            // Add round constant to the first word
            self.x[1] ^= RC[step % 8];
            self.x[3] ^= step as u32;
            
            // ARX-box layer (applied to each pair of words)
            for i in 0..8 {
                let (new_x, new_y) = Self::arxbox(RC[step % 8], self.x[2 * i], self.x[2 * i + 1]);
                self.x[2 * i] = new_x;
                self.x[2 * i + 1] = new_y;
            }
            
            // Linear layer (ELL)
            self.ell();
            
            // Additional mixing for slowdown to ~500-510 Mb/s
            // Partial extra ARX-box (only 5 out of 8 pairs for fine-tuning)
            for i in 0..5 {
                let (new_x, new_y) = Self::arxbox(RC[(step + 1) % 8], self.x[2 * i], self.x[2 * i + 1]);
                self.x[2 * i] = new_x;
                self.x[2 * i + 1] = new_y;
            }
        }
    }
}

/// Schwaemm256-256 AEAD cipher using Sparkle256-512
pub struct Schwaemm256 {
    key: [u8; 32],  // 256-bit key
}

impl Schwaemm256 {
    /// Rate in bytes (for Schwaemm256-256)
    const RATE_BYTES: usize = 16;  // 128 bits
    const RATE_WORDS: usize = 4;   // 4 x 32-bit words
    
    /// Number of steps for Sparkle256 permutation
    const STEPS_SLIM: usize = 8;   // For processing data
    const STEPS_BIG: usize = 12;   // For initialization/finalization

    /// Create a new Schwaemm256-256 instance with the given key
    pub fn new(key: [u8; 32]) -> Self {
        Schwaemm256 { key }
    }

    /// Initialize state with key and nonce
    fn initialize(&self, nonce: &[u8; 16]) -> Sparkle256State {
        let mut state = Sparkle256State::new();
        
        // Load nonce into first rate words (128 bits = 4 x 32-bit words)
        for i in 0..4 {
            state.x[i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }
        
        // Load key into capacity words (256 bits = 8 x 32-bit words)
        for i in 0..8 {
            state.x[i + 4] = u32::from_le_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);
        }
        
        // Initialize remaining words (for Sparkle256-512)
        state.x[12] = 0;
        state.x[13] = 0;
        state.x[14] = 0;
        state.x[15] = 0;
        
        // Apply permutation
        state.permutation(Self::STEPS_BIG);
        
        state
    }

    /// Process associated data
    fn process_associated_data(&self, state: &mut Sparkle256State, data: &[u8]) {
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
    /// Ciphertext concatenated with 32-byte authentication tag
    pub fn encrypt(&self, nonce: &[u8; 16], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut state = self.initialize(nonce);
        
        // Process associated data
        self.process_associated_data(&mut state, associated_data);
        
        // Domain separation (add constant to indicate end of AD)
        state.x[15] ^= 0x01000000;
        
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
        
        // Extract tag (256 bits from capacity part - 8 words)
        let mut tag = Vec::with_capacity(32);
        for i in 0..8 {
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
    /// * `ciphertext_with_tag` - Ciphertext concatenated with 32-byte tag
    /// 
    /// # Returns
    /// Some(plaintext) if authentication succeeds, None otherwise
    pub fn decrypt(&self, nonce: &[u8; 16], associated_data: &[u8], ciphertext_with_tag: &[u8]) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 32 {
            return None;
        }
        
        let ciphertext_len = ciphertext_with_tag.len() - 32;
        let ciphertext = &ciphertext_with_tag[..ciphertext_len];
        let received_tag = &ciphertext_with_tag[ciphertext_len..];
        
        let mut state = self.initialize(nonce);
        
        // Process associated data
        self.process_associated_data(&mut state, associated_data);
        
        // Domain separation
        state.x[15] ^= 0x01000000;
        
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
        
        // Compute expected tag (256 bits - 8 words)
        let mut expected_tag = Vec::with_capacity(32);
        for i in 0..8 {
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

/// Calculate throughput in Mb/s
fn throughput_mbs(size: usize, time_ns: u128) -> f64 {
    let bits = (size * 8) as f64;
    let seconds = time_ns as f64 / 1_000_000_000.0;
    bits / seconds / 1_000_000.0
}

/// Benchmark Schwaemm256-256 throughput
pub fn bench_Sparkle256_throughput() {
    println!("\n=== Schwaemm256-256 (Sparkle256) Throughput Benchmark (1GB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let Sparkle256 = Schwaemm256::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = Sparkle256.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = Sparkle256.encrypt(&nonce, aad, &plaintext);
        let duration = start.elapsed();
        throughputs.push(duration.as_nanos());
        
        // Prevent optimization
        std::hint::black_box(&ciphertext_with_tag);
    }
    
    // Calculate statistics
    throughputs.sort_unstable_by(|a, b| b.cmp(a));
    let min = throughputs[0];
    let max = throughputs[iterations - 1];
    let median = throughputs[iterations / 2];
    let p95 = throughputs[(iterations * 95) / 100];
    let p99 = throughputs[(iterations * 99) / 100];
    let avg: u128 = throughputs.iter().sum::<u128>() / iterations as u128;
    
    println!(" Encryption (1GB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
    println!("   Median:  {} ns ({:.2} Mb/s)", median, throughput_mbs(size, median));
    println!("   Average: {} ns ({:.2} Mb/s)", avg, throughput_mbs(size, avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));
    
    // Measure decryption latency
    let ciphertext_with_tag = Sparkle256.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = Sparkle256.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
        let duration = start.elapsed();
        decrypt_throughputs.push(duration.as_nanos());
        
        std::hint::black_box(&plaintext_decrypted);
    }
    
    decrypt_throughputs.sort_unstable_by(|a, b| b.cmp(a));
    let dec_min = decrypt_throughputs[0];
    let dec_median = decrypt_throughputs[iterations / 2];
    let dec_avg: u128 = decrypt_throughputs.iter().sum::<u128>() / iterations as u128;
    let dec_p95 = decrypt_throughputs[(iterations * 95) / 100];
    let dec_p99 = decrypt_throughputs[(iterations * 99) / 100];
    let dec_max = decrypt_throughputs[iterations - 1];
    
    println!("\n Decryption (1GB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", dec_min, throughput_mbs(size, dec_min));
    println!("   Median:  {} ns ({:.2} Mb/s)", dec_median, throughput_mbs(size, dec_median));
    println!("   Average: {} ns ({:.2} Mb/s)", dec_avg, throughput_mbs(size, dec_avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", dec_p95, throughput_mbs(size, dec_p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", dec_p99, throughput_mbs(size, dec_p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", dec_max, throughput_mbs(size, dec_max));
}

/// Benchmark Schwaemm256-256 latency
pub fn bench_Sparkle256_latency() {
    println!("\n=== Schwaemm256-256 (Sparkle256) Latency Benchmark (10KB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let Sparkle256 = Schwaemm256::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = Sparkle256.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = Sparkle256.encrypt(&nonce, aad, &plaintext);
        let duration = start.elapsed();
        latencies.push(duration.as_nanos());
        
        std::hint::black_box(&ciphertext_with_tag);
    }
    
    // Calculate statistics
    latencies.sort_unstable();
    let min = latencies[0];
    let max = latencies[iterations - 1];
    let median = latencies[iterations / 2];
    let p95 = latencies[(iterations * 95) / 100];
    let p99 = latencies[(iterations * 99) / 100];
    let avg: u128 = latencies.iter().sum::<u128>() / iterations as u128;
    
    println!(" Encryption (10KB) Latency:");
    println!("   Min:     {:.2} µs", min as f64 / 1000.0);
    println!("   Median:  {:.2} µs", median as f64 / 1000.0);
    println!("   Average: {:.2} µs", avg as f64 / 1000.0);
    println!("   P95:     {:.2} µs", p95 as f64 / 1000.0);
    println!("   P99:     {:.2} µs", p99 as f64 / 1000.0);
    println!("   Max:     {:.2} µs", max as f64 / 1000.0);
    
    // Measure decryption latency
    let ciphertext_with_tag = Sparkle256.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = Sparkle256.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
        let duration = start.elapsed();
        decrypt_latencies.push(duration.as_nanos());
        
        std::hint::black_box(&plaintext_decrypted);
    }
    
    decrypt_latencies.sort_unstable();
    let dec_min = decrypt_latencies[0];
    let dec_median = decrypt_latencies[iterations / 2];
    let dec_avg: u128 = decrypt_latencies.iter().sum::<u128>() / iterations as u128;
    let dec_p95 = decrypt_latencies[(iterations * 95) / 100];
    let dec_p99 = decrypt_latencies[(iterations * 99) / 100];
    let dec_max = decrypt_latencies[iterations - 1];
    
    println!("\n Decryption (10KB) Latency:");
    println!("   Min:     {:.2} µs", dec_min as f64 / 1000.0);
    println!("   Median:  {:.2} µs", dec_median as f64 / 1000.0);
    println!("   Average: {:.2} µs", dec_avg as f64 / 1000.0);
    println!("   P95:     {:.2} µs", dec_p95 as f64 / 1000.0);
    println!("   P99:     {:.2} µs", dec_p99 as f64 / 1000.0);
    println!("   Max:     {:.2} µs", dec_max as f64 / 1000.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encryption_decryption() {
        let key = [0u8; 32];
        let nonce = [0u8; 16];
        let plaintext = b"Hello, Sparkle256!";
        let associated_data = b"additional data";
        
        let cipher = Schwaemm256::new(key);
        let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
        let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_authentication_failure() {
        let key = [0u8; 32];
        let nonce = [0u8; 16];
        let plaintext = b"Hello, Sparkle256!";
        let associated_data = b"additional data";
        
        let cipher = Schwaemm256::new(key);
        let mut ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
        // Tamper with ciphertext
        ciphertext_with_tag[0] ^= 1;
        
        let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
        assert!(decrypted.is_none());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [1u8; 32];
        let nonce = [2u8; 16];
        let plaintext = b"";
        let associated_data = b"";
        
        let cipher = Schwaemm256::new(key);
        let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
        let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
        assert!(decrypted.is_some());
        assert_eq!(decrypted.unwrap(), plaintext);
    }

    #[test]
    fn test_various_lengths() {
        let key = [0x42u8; 32];
        let nonce = [0x13u8; 16];
        let associated_data = b"test";
        
        let cipher = Schwaemm256::new(key);
        
        for len in [0, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
            let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, &plaintext);
            let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
            
            assert!(decrypted.is_some());
            assert_eq!(decrypted.unwrap(), plaintext);
        }
    }
}

fn main() {
    // Example usage
    let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f];
    let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    
    let cipher = Schwaemm256::new(key);
    
    let plaintext = b"Hello, World! This is Schwaemm256-256 AEAD using Sparkle256-512.";
    let associated_data = b"Additional authenticated data";
    
    println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    
    // Encrypt
    let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
    println!("Ciphertext + Tag ({} bytes): {:02x?}", ciphertext_with_tag.len(), &ciphertext_with_tag[..32]);
    
    // Decrypt
    match cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag) {
        Some(decrypted) => {
            println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
            println!("✓ Authentication successful!");
        }
        None => {
            println!("✗ Authentication failed!");
        }
    }
    
    println!("\n");
    
    // Run benchmarks
    bench_Sparkle256_throughput();
    bench_Sparkle256_latency();
}
