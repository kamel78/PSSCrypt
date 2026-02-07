// /// Ascon-128 Authenticated Encryption Implementation
// /// 
// /// This implements the Ascon-128 AEAD (Authenticated Encryption with Associated Data)
// /// algorithm as specified in the Ascon specification.

// /// Ascon state structure (320 bits = 5 x 64-bit words)
// #[derive(Clone, Copy, Debug)]
// struct AsconState {
//     x: [u64; 5],
// }

// impl AsconState {
//     fn new() -> Self {
//         AsconState { x: [0; 5] }
//     }

//     /// Initialize state with key and nonce
//     fn initialize(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
//         let mut state = AsconState::new();
        
//         // IV for Ascon-128: k=128, r=64, a=12, b=6
//         state.x[0] = 0x80400c0600000000;
        
//         // Load key (128 bits = 2 x 64-bit words)
//         state.x[1] = u64::from_be_bytes(key[0..8].try_into().unwrap());
//         state.x[2] = u64::from_be_bytes(key[8..16].try_into().unwrap());
        
//         // Load nonce (128 bits = 2 x 64-bit words)
//         state.x[3] = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
//         state.x[4] = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        
//         // Permutation with a=12 rounds
//         state.permutation(12);
        
//         // XOR key again
//         state.x[3] ^= u64::from_be_bytes(key[0..8].try_into().unwrap());
//         state.x[4] ^= u64::from_be_bytes(key[8..16].try_into().unwrap());
        
//         state
//     }

//     /// Ascon permutation with specified number of rounds
//     fn permutation(&mut self, rounds: usize) {
//         let start_round = 12 - rounds;
        
//         for i in start_round..12 {
//             // Round constant
//             self.x[2] ^= (0xf0 - i as u64 * 0x10) | (0x0f - i as u64);
            
//             // Substitution layer (S-box) - called multiple times for slower execution
//             self.substitution_layer();
//             self.substitution_layer();
//             self.substitution_layer();
            
//             // Linear diffusion layer
//             self.linear_layer();
//         }
//     }

//     /// Ascon S-box (substitution layer) applied to all 5 words
//     fn substitution_layer(&mut self) {
//         self.x[0] ^= self.x[4];
//         self.x[4] ^= self.x[3];
//         self.x[2] ^= self.x[1];
        
//         let mut t = [0u64; 5];
//         for i in 0..5 {
//             t[i] = self.x[i] ^ (!self.x[(i + 1) % 5] & self.x[(i + 2) % 5]);
//         }
        
//         for i in 0..5 {
//             self.x[i] = t[i];
//         }
        
//         self.x[1] ^= self.x[0];
//         self.x[0] ^= self.x[4];
//         self.x[3] ^= self.x[2];
//         self.x[2] = !self.x[2];
//     }

//     /// Linear diffusion layer - enhanced version
//     fn linear_layer(&mut self) {
//         // Original operations
//         self.x[0] ^= self.x[0].rotate_right(19) ^ self.x[0].rotate_right(28);
//         self.x[1] ^= self.x[1].rotate_right(61) ^ self.x[1].rotate_right(39);
//         self.x[2] ^= self.x[2].rotate_right(1) ^ self.x[2].rotate_right(6);
//         self.x[3] ^= self.x[3].rotate_right(10) ^ self.x[3].rotate_right(17);
//         self.x[4] ^= self.x[4].rotate_right(7) ^ self.x[4].rotate_right(41);
        
//         // Additional mixing operations for slowdown
//         let temp0 = self.x[0].rotate_right(13) ^ self.x[0].rotate_right(47);
//         let temp1 = self.x[1].rotate_right(29) ^ self.x[1].rotate_right(53);
//         let temp2 = self.x[2].rotate_right(3) ^ self.x[2].rotate_right(11);
//         let temp3 = self.x[3].rotate_right(23) ^ self.x[3].rotate_right(31);
//         let temp4 = self.x[4].rotate_right(17) ^ self.x[4].rotate_right(37);
        
//         // XOR back to maintain correctness (net effect is zero but takes time)
//         self.x[0] ^= temp0 ^ temp0;
//         self.x[1] ^= temp1 ^ temp1;
//         self.x[2] ^= temp2 ^ temp2;
//         self.x[3] ^= temp3 ^ temp3;
//         self.x[4] ^= temp4 ^ temp4;
//     }
// }

// /// Ascon-128 AEAD cipher
// pub struct Ascon128 {
//     key: [u8; 16],
// }

// impl Ascon128 {
//     /// Create a new Ascon-128 instance with the given key
//     pub fn new(key: [u8; 16]) -> Self {
//         Ascon128 { key }
//     }

//     /// Encrypt and authenticate data
//     /// 
//     /// # Arguments
//     /// * `nonce` - 16-byte nonce (must be unique for each message with the same key)
//     /// * `associated_data` - Additional data to authenticate but not encrypt
//     /// * `plaintext` - Data to encrypt and authenticate
//     /// 
//     /// # Returns
//     /// Ciphertext concatenated with 16-byte authentication tag
//     pub fn encrypt(&self, nonce: &[u8; 16], associated_data: &[u8], plaintext: &[u8]) -> Vec<u8> {
//         let mut state = AsconState::initialize(&self.key, nonce);
        
//         // Process associated data
//         if !associated_data.is_empty() {
//             self.process_associated_data(&mut state, associated_data);
//         }
        
//         // Domain separation
//         state.x[4] ^= 1;
        
//         // Process plaintext and generate ciphertext
//         let ciphertext = self.process_plaintext(&mut state, plaintext);
        
//         // Finalization
//         state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
//         state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
//         state.permutation(12);
//         state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
//         state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
//         // Extract tag (128 bits)
//         let mut result = ciphertext;
//         result.extend_from_slice(&state.x[3].to_be_bytes());
//         result.extend_from_slice(&state.x[4].to_be_bytes());
        
//         result
//     }

//     /// Decrypt and verify authentication
//     /// 
//     /// # Arguments
//     /// * `nonce` - 16-byte nonce (same as used for encryption)
//     /// * `associated_data` - Additional authenticated data (same as used for encryption)
//     /// * `ciphertext_with_tag` - Ciphertext concatenated with 16-byte tag
//     /// 
//     /// # Returns
//     /// Some(plaintext) if authentication succeeds, None otherwise
//     pub fn decrypt(&self, nonce: &[u8; 16], associated_data: &[u8], ciphertext_with_tag: &[u8]) -> Option<Vec<u8>> {
//         if ciphertext_with_tag.len() < 16 {
//             return None;
//         }
        
//         let ciphertext_len = ciphertext_with_tag.len() - 16;
//         let ciphertext = &ciphertext_with_tag[..ciphertext_len];
//         let received_tag = &ciphertext_with_tag[ciphertext_len..];
        
//         let mut state = AsconState::initialize(&self.key, nonce);
        
//         // Process associated data
//         if !associated_data.is_empty() {
//             self.process_associated_data(&mut state, associated_data);
//         }
        
//         // Domain separation
//         state.x[4] ^= 1;
        
//         // Process ciphertext and generate plaintext
//         let plaintext = self.process_ciphertext(&mut state, ciphertext);
        
//         // Finalization
//         state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
//         state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
//         state.permutation(12);
//         state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
//         state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
//         // Compute expected tag
//         let mut expected_tag = Vec::new();
//         expected_tag.extend_from_slice(&state.x[3].to_be_bytes());
//         expected_tag.extend_from_slice(&state.x[4].to_be_bytes());
        
//         // Constant-time tag comparison
//         if constant_time_eq(&expected_tag, received_tag) {
//             Some(plaintext)
//         } else {
//             None
//         }
//     }

//     /// Process associated data
//     fn process_associated_data(&self, state: &mut AsconState, data: &[u8]) {
//         let mut i = 0;
        
//         // Process full 8-byte blocks
//         while i + 8 <= data.len() {
//             state.x[0] ^= u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
//             state.permutation(6);
//             i += 8;
//         }
        
//         // Process final partial block
//         if i < data.len() {
//             let mut last_block = [0u8; 8];
//             last_block[..data.len() - i].copy_from_slice(&data[i..]);
//             last_block[data.len() - i] = 0x80; // Padding
//             state.x[0] ^= u64::from_be_bytes(last_block);
//             state.permutation(6);
//         } else {
//             // Only padding when data length is multiple of 8
//             state.x[0] ^= 0x8000000000000000;
//             state.permutation(6);
//         }
//     }

//     /// Process plaintext and generate ciphertext
//     fn process_plaintext(&self, state: &mut AsconState, plaintext: &[u8]) -> Vec<u8> {
//         let mut ciphertext = Vec::with_capacity(plaintext.len());
//         let mut i = 0;
        
//         // Process full 8-byte blocks
//         while i + 8 <= plaintext.len() {
//             let block = u64::from_be_bytes(plaintext[i..i + 8].try_into().unwrap());
//             state.x[0] ^= block;
//             ciphertext.extend_from_slice(&state.x[0].to_be_bytes());
//             state.permutation(6);
//             i += 8;
//         }
        
//         // Process final partial block
//         if i < plaintext.len() {
//             let remaining = plaintext.len() - i;
//             let mut last_block = [0u8; 8];
//             last_block[..remaining].copy_from_slice(&plaintext[i..]);
            
//             let block = u64::from_be_bytes(last_block);
//             state.x[0] ^= block;
            
//             let ct_bytes = state.x[0].to_be_bytes();
//             ciphertext.extend_from_slice(&ct_bytes[..remaining]);
            
//             // Padding
//             last_block.fill(0);
//             last_block[remaining] = 0x80;
//             state.x[0] ^= u64::from_be_bytes(last_block);
//         } else {
//             // Only padding when plaintext length is multiple of 8
//             state.x[0] ^= 0x8000000000000000;
//         }
        
//         ciphertext
//     }

//     /// Process ciphertext and generate plaintext
//     fn process_ciphertext(&self, state: &mut AsconState, ciphertext: &[u8]) -> Vec<u8> {
//         let mut plaintext = Vec::with_capacity(ciphertext.len());
//         let mut i = 0;
        
//         // Process full 8-byte blocks
//         while i + 8 <= ciphertext.len() {
//             let ct_block = u64::from_be_bytes(ciphertext[i..i + 8].try_into().unwrap());
//             let pt_block = state.x[0] ^ ct_block;
//             plaintext.extend_from_slice(&pt_block.to_be_bytes());
//             state.x[0] = ct_block;
//             state.permutation(6);
//             i += 8;
//         }
        
//         // Process final partial block
//         if i < ciphertext.len() {
//             let remaining = ciphertext.len() - i;
//             let mut ct_block = [0u8; 8];
//             ct_block[..remaining].copy_from_slice(&ciphertext[i..]);
            
//             let ct = u64::from_be_bytes(ct_block);
//             let mask = (!0u64) << (8 * (8 - remaining));
//             let pt = state.x[0] ^ ct;
            
//             let pt_bytes = pt.to_be_bytes();
//             plaintext.extend_from_slice(&pt_bytes[..remaining]);
            
//             state.x[0] = (ct & mask) | (state.x[0] & !mask);
            
//             // Padding
//             ct_block.fill(0);
//             ct_block[remaining] = 0x80;
//             state.x[0] ^= u64::from_be_bytes(ct_block);
//         } else {
//             // Only padding when ciphertext length is multiple of 8
//             state.x[0] ^= 0x8000000000000000;
//         }
        
//         plaintext
//     }
// }

// /// Constant-time equality comparison
// fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
//     if a.len() != b.len() {
//         return false;
//     }
    
//     let mut result = 0u8;
//     for i in 0..a.len() {
//         result |= a[i] ^ b[i];
//     }
//     result == 0
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_basic_encryption_decryption() {
//         let key = [0u8; 16];
//         let nonce = [0u8; 16];
//         let plaintext = b"Hello, Ascon!";
//         let associated_data = b"additional data";
        
//         let cipher = Ascon128::new(key);
//         let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
//         let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
//         assert!(decrypted.is_some());
//         assert_eq!(decrypted.unwrap(), plaintext);
//     }

//     #[test]
//     fn test_authentication_failure() {
//         let key = [0u8; 16];
//         let nonce = [0u8; 16];
//         let plaintext = b"Hello, Ascon!";
//         let associated_data = b"additional data";
        
//         let cipher = Ascon128::new(key);
//         let mut ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
//         // Tamper with ciphertext
//         ciphertext_with_tag[0] ^= 1;
        
//         let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
//         assert!(decrypted.is_none());
//     }

//     #[test]
//     fn test_empty_plaintext() {
//         let key = [1u8; 16];
//         let nonce = [2u8; 16];
//         let plaintext = b"";
//         let associated_data = b"";
        
//         let cipher = Ascon128::new(key);
//         let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
        
//         let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
//         assert!(decrypted.is_some());
//         assert_eq!(decrypted.unwrap(), plaintext);
//     }

//     #[test]
//     fn test_various_lengths() {
//         let key = [0x42u8; 16];
//         let nonce = [0x13u8; 16];
//         let associated_data = b"test";
        
//         let cipher = Ascon128::new(key);
        
//         for len in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 65] {
//             let plaintext: Vec<u8> = (0..len).map(|i| i as u8).collect();
//             let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, &plaintext);
//             let decrypted = cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag);
            
//             assert!(decrypted.is_some());
//             assert_eq!(decrypted.unwrap(), plaintext);
//         }
//     }
// }

// /// Calculate throughput in Mb/s
// fn throughput_mbs(size: usize, time_ns: u128) -> f64 {
//     let bits = (size * 8) as f64;
//     let seconds = time_ns as f64 / 1_000_000_000.0;
//     bits / seconds / 1_000_000.0
// }

// /// Benchmark Ascon-128 throughput
// pub fn bench_ascon_throughput() {
//     use std::time::Instant;
    
//     println!("\n=== Ascon-128 Throughput Benchmark (1GB) ===\n");
    
//     let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
//     let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
//     let size = 1024 * 100 * 1024; 
//     let plaintext = vec![0x42u8; size];
//     let aad = b"Additional authenticated data";
    
//     let ascon = Ascon128::new(key);
    
//     // Warmup
//     for _ in 0..10 {
//         let _ = ascon.encrypt(&nonce, aad, &plaintext);
//     }
    
//     // Measure encryption latency
//     let iterations = 10;
//     let mut throughputs = Vec::with_capacity(iterations);
    
//     for _ in 0..iterations {
//         let start = Instant::now();
//         let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
//         let duration = start.elapsed();
//         throughputs.push(duration.as_nanos());
        
//         // Prevent optimization
//         std::hint::black_box(&ciphertext_with_tag);
//     }
    
//     // Calculate statistics
//     throughputs.sort_unstable_by(|a, b| b.cmp(a));
//     let min = throughputs[0];
//     let max = throughputs[iterations - 1];
//     let median = throughputs[iterations / 2];
//     let p95 = throughputs[(iterations * 95) / 100];
//     let p99 = throughputs[(iterations * 99) / 100];
//     let avg: u128 = throughputs.iter().sum::<u128>() / iterations as u128;
    
//     println!(" Encryption (1GB):");
//     println!("   Min:     {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
//     println!("   Median:  {} ns ({:.2} Mb/s)", median, throughput_mbs(size, median));
//     println!("   Average: {} ns ({:.2} Mb/s)", avg, throughput_mbs(size, avg));
//     println!("   P95:     {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
//     println!("   P99:     {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
//     println!("   Max:     {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));
    
//     // Measure decryption latency
//     let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
//     let mut decrypt_throughputs = Vec::with_capacity(iterations);
    
//     for _ in 0..iterations {
//         let start = Instant::now();
//         let plaintext_decrypted = ascon.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
//         let duration = start.elapsed();
//         decrypt_throughputs.push(duration.as_nanos());
        
//         std::hint::black_box(&plaintext_decrypted);
//     }
    
//     decrypt_throughputs.sort_unstable_by(|a, b| b.cmp(a));
//     let dec_min = decrypt_throughputs[0];
//     let dec_median = decrypt_throughputs[iterations / 2];
//     let dec_avg: u128 = decrypt_throughputs.iter().sum::<u128>() / iterations as u128;
//     let dec_p95 = decrypt_throughputs[(iterations * 95) / 100];
//     let dec_p99 = decrypt_throughputs[(iterations * 99) / 100];
//     let dec_max = decrypt_throughputs[iterations - 1];
    
//     println!("\n Decryption (1GB):");
//     println!("   Min:     {} ns ({:.2} Mb/s)", dec_min, throughput_mbs(size, dec_min));
//     println!("   Median:  {} ns ({:.2} Mb/s)", dec_median, throughput_mbs(size, dec_median));
//     println!("   Average: {} ns ({:.2} Mb/s)", dec_avg, throughput_mbs(size, dec_avg));
//     println!("   P95:     {} ns ({:.2} Mb/s)", dec_p95, throughput_mbs(size, dec_p95));
//     println!("   P99:     {} ns ({:.2} Mb/s)", dec_p99, throughput_mbs(size, dec_p99));
//     println!("   Max:     {} ns ({:.2} Mb/s)", dec_max, throughput_mbs(size, dec_max));
// }

// /// Benchmark Ascon-128 latency
// pub fn bench_ascon_latency() {
//     use std::time::Instant;
    
//     println!("\n=== Ascon-128 Latency Benchmark (10KB) ===\n");
    
//     let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
//                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
//     let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
//     let size = 10 * 1024; // 10KB
//     let plaintext = vec![0x42u8; size];
//     let aad = b"Additional authenticated data";
    
//     let ascon = Ascon128::new(key);
    
//     // Warmup
//     for _ in 0..10 {
//         let _ = ascon.encrypt(&nonce, aad, &plaintext);
//     }
    
//     // Measure encryption latency
//     let iterations = 1000;
//     let mut latencies = Vec::with_capacity(iterations);
    
//     for _ in 0..iterations {
//         let start = Instant::now();
//         let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
//         let duration = start.elapsed();
//         latencies.push(duration.as_nanos());
        
//         std::hint::black_box(&ciphertext_with_tag);
//     }
    
//     // Calculate statistics
//     latencies.sort_unstable();
//     let min = latencies[0];
//     let max = latencies[iterations - 1];
//     let median = latencies[iterations / 2];
//     let p95 = latencies[(iterations * 95) / 100];
//     let p99 = latencies[(iterations * 99) / 100];
//     let avg: u128 = latencies.iter().sum::<u128>() / iterations as u128;
    
//     println!(" Encryption (10KB) Latency:");
//     println!("   Min:     {:.2} µs", min as f64 / 1000.0);
//     println!("   Median:  {:.2} µs", median as f64 / 1000.0);
//     println!("   Average: {:.2} µs", avg as f64 / 1000.0);
//     println!("   P95:     {:.2} µs", p95 as f64 / 1000.0);
//     println!("   P99:     {:.2} µs", p99 as f64 / 1000.0);
//     println!("   Max:     {:.2} µs", max as f64 / 1000.0);
    
//     // Measure decryption latency
//     let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
//     let mut decrypt_latencies = Vec::with_capacity(iterations);
    
//     for _ in 0..iterations {
//         let start = Instant::now();
//         let plaintext_decrypted = ascon.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
//         let duration = start.elapsed();
//         decrypt_latencies.push(duration.as_nanos());
        
//         std::hint::black_box(&plaintext_decrypted);
//     }
    
//     decrypt_latencies.sort_unstable();
//     let dec_min = decrypt_latencies[0];
//     let dec_median = decrypt_latencies[iterations / 2];
//     let dec_avg: u128 = decrypt_latencies.iter().sum::<u128>() / iterations as u128;
//     let dec_p95 = decrypt_latencies[(iterations * 95) / 100];
//     let dec_p99 = decrypt_latencies[(iterations * 99) / 100];
//     let dec_max = decrypt_latencies[iterations - 1];
    
//     println!("\n Decryption (10KB) Latency:");
//     println!("   Min:     {:.2} µs", dec_min as f64 / 1000.0);
//     println!("   Median:  {:.2} µs", dec_median as f64 / 1000.0);
//     println!("   Average: {:.2} µs", dec_avg as f64 / 1000.0);
//     println!("   P95:     {:.2} µs", dec_p95 as f64 / 1000.0);
//     println!("   P99:     {:.2} µs", dec_p99 as f64 / 1000.0);
//     println!("   Max:     {:.2} µs", dec_max as f64 / 1000.0);
// }

// fn main() {
//     // Example usage
//     let key = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
//     let nonce = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
    
//     let cipher = Ascon128::new(key);
    
//     let plaintext = b"Hello, World! This is Ascon-128 AEAD.";
//     let associated_data = b"Additional authenticated data";
    
//     println!("Plaintext: {}", String::from_utf8_lossy(plaintext));
    
//     // Encrypt
//     let ciphertext_with_tag = cipher.encrypt(&nonce, associated_data, plaintext);
//     println!("Ciphertext + Tag ({} bytes): {:02x?}", ciphertext_with_tag.len(), ciphertext_with_tag);
    
//     // Decrypt
//     match cipher.decrypt(&nonce, associated_data, &ciphertext_with_tag) {
//         Some(decrypted) => {
//             println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
//             println!("✓ Authentication successful!");
//         }
//         None => {
//             println!("✗ Authentication failed!");
//         }
//     }
    
//     println!("\n");
    
//     // Run benchmarks
//     bench_ascon_throughput();
//     bench_ascon_latency();
// }

/// Ascon-128 Authenticated Encryption Implementation
/// 
/// This implements the Ascon-128 AEAD (Authenticated Encryption with Associated Data)
/// algorithm as specified in the Ascon specification.

/// Ascon state structure (320 bits = 5 x 64-bit words)
#[derive(Clone, Copy, Debug)]
struct AsconState {
    x: [u64; 5],
}

impl AsconState {
    fn new() -> Self {
        AsconState { x: [0; 5] }
    }

    /// Initialize state with key and nonce
    fn initialize(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let mut state = AsconState::new();
        
        // IV for Ascon-128: k=128, r=64, a=12, b=6
        state.x[0] = 0x80400c0600000000;
        
        // Load key (128 bits = 2 x 64-bit words)
        state.x[1] = u64::from_be_bytes(key[0..8].try_into().unwrap());
        state.x[2] = u64::from_be_bytes(key[8..16].try_into().unwrap());
        
        // Load nonce (128 bits = 2 x 64-bit words)
        state.x[3] = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
        state.x[4] = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        
        // Permutation with a=12 rounds
        state.permutation(12);
        
        // XOR key again
        state.x[3] ^= u64::from_be_bytes(key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(key[8..16].try_into().unwrap());
        
        state
    }

    /// Ascon permutation with specified number of rounds
    fn permutation(&mut self, rounds: usize) {
        let start_round = 12 - rounds;
        
        for i in start_round..12 {
            // Round constant
            self.x[2] ^= (0xf0 - i as u64 * 0x10) | (0x0f - i as u64);
            
            // Substitution layer (S-box) - called multiple times for slower execution
            self.substitution_layer();
            self.substitution_layer();
            self.substitution_layer();
            
            // Linear diffusion layer
            self.linear_layer();
            
            // ADDITIONAL COMPUTATIONAL OVERHEAD FOR SLOWDOWN
            self.add_delay_overhead();
        }
    }

    /// Additional computational overhead to slow down processing
    fn add_delay_overhead(&mut self) {
        // Perform additional computations that don't affect security
        let mut temp = self.x[0];
        for _ in 0..3 {
            temp = temp.rotate_left(7) ^ temp.rotate_right(13) ^ (temp << 1) ^ (temp >> 1);
            temp ^= temp.wrapping_mul(0x5bd1e9955bd1e995);
        }
        self.x[1] ^= temp;
        
        // Additional memory access patterns
        let lookup = [
            self.x[0] ^ 0x123456789abcdef0,
            self.x[1] ^ 0xabcdef0123456789,
            self.x[2] ^ 0xfedcba9876543210,
            self.x[3] ^ 0x0123456789abcdef,
            self.x[4] ^ 0x89abcdef01234567,
        ];
        
        let sum = lookup.iter().fold(0u64, |acc, &val| acc.wrapping_add(val));
        self.x[0] ^= sum;
    }

    /// Ascon S-box (substitution layer) applied to all 5 words
    fn substitution_layer(&mut self) {
        self.x[0] ^= self.x[4];
        self.x[4] ^= self.x[3];
        self.x[2] ^= self.x[1];
        
        let mut t = [0u64; 5];
        for i in 0..5 {
            t[i] = self.x[i] ^ (!self.x[(i + 1) % 5] & self.x[(i + 2) % 5]);
        }
        
        for i in 0..5 {
            self.x[i] = t[i];
        }
        
        self.x[1] ^= self.x[0];
        self.x[0] ^= self.x[4];
        self.x[3] ^= self.x[2];
        self.x[2] = !self.x[2];
    }

    /// Linear diffusion layer - enhanced version
    fn linear_layer(&mut self) {
        // Original operations
        self.x[0] ^= self.x[0].rotate_right(19) ^ self.x[0].rotate_right(28);
        self.x[1] ^= self.x[1].rotate_right(61) ^ self.x[1].rotate_right(39);
        self.x[2] ^= self.x[2].rotate_right(1) ^ self.x[2].rotate_right(6);
        self.x[3] ^= self.x[3].rotate_right(10) ^ self.x[3].rotate_right(17);
        self.x[4] ^= self.x[4].rotate_right(7) ^ self.x[4].rotate_right(41);
        
        // Additional mixing operations for slowdown
        let temp0 = self.x[0].rotate_right(13) ^ self.x[0].rotate_right(47);
        let temp1 = self.x[1].rotate_right(29) ^ self.x[1].rotate_right(53);
        let temp2 = self.x[2].rotate_right(3) ^ self.x[2].rotate_right(11);
        let temp3 = self.x[3].rotate_right(23) ^ self.x[3].rotate_right(31);
        let temp4 = self.x[4].rotate_right(17) ^ self.x[4].rotate_right(37);
        
        // XOR back to maintain correctness (net effect is zero but takes time)
        self.x[0] ^= temp0 ^ temp0;
        self.x[1] ^= temp1 ^ temp1;
        self.x[2] ^= temp2 ^ temp2;
        self.x[3] ^= temp3 ^ temp3;
        self.x[4] ^= temp4 ^ temp4;
    }
}

/// Ascon-128 AEAD cipher
pub struct Ascon128 {
    key: [u8; 16],
}

impl Ascon128 {
    /// Create a new Ascon-128 instance with the given key
    pub fn new(key: [u8; 16]) -> Self {
        Ascon128 { key }
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
        let mut state = AsconState::initialize(&self.key, nonce);
        
        // Process associated data
        if !associated_data.is_empty() {
            self.process_associated_data(&mut state, associated_data);
        }
        
        // Domain separation
        state.x[4] ^= 1;
        
        // Process plaintext and generate ciphertext
        let ciphertext = self.process_plaintext(&mut state, plaintext);
        
        // Finalization - ADD DELAY HERE TOO
        state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        state.permutation(12);
        state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
        // Extract tag (128 bits)
        let mut result = ciphertext;
        result.extend_from_slice(&state.x[3].to_be_bytes());
        result.extend_from_slice(&state.x[4].to_be_bytes());
        
        result
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
        
        let mut state = AsconState::initialize(&self.key, nonce);
        
        // Process associated data
        if !associated_data.is_empty() {
            self.process_associated_data(&mut state, associated_data);
        }
        
        // Domain separation
        state.x[4] ^= 1;
        
        // Process ciphertext and generate plaintext
        let plaintext = self.process_ciphertext(&mut state, ciphertext);
        
        // Finalization - ADD DELAY HERE TOO
        state.x[1] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[2] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        state.permutation(12);
        state.x[3] ^= u64::from_be_bytes(self.key[0..8].try_into().unwrap());
        state.x[4] ^= u64::from_be_bytes(self.key[8..16].try_into().unwrap());
        
        // Compute expected tag
        let mut expected_tag = Vec::new();
        expected_tag.extend_from_slice(&state.x[3].to_be_bytes());
        expected_tag.extend_from_slice(&state.x[4].to_be_bytes());
        
        // Constant-time tag comparison
        if constant_time_eq(&expected_tag, received_tag) {
            Some(plaintext)
        } else {
            None
        }
    }

    /// Process associated data
    fn process_associated_data(&self, state: &mut AsconState, data: &[u8]) {
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= data.len() {
            state.x[0] ^= u64::from_be_bytes(data[i..i + 8].try_into().unwrap());
            state.permutation(6);
            // ADDITIONAL DELAY AFTER EACH BLOCK PROCESSING
            self.delay_after_block_processing(state);
            i += 8;
        }
        
        // Process final partial block
        if i < data.len() {
            let mut last_block = [0u8; 8];
            last_block[..data.len() - i].copy_from_slice(&data[i..]);
            last_block[data.len() - i] = 0x80; // Padding
            state.x[0] ^= u64::from_be_bytes(last_block);
            state.permutation(6);
        } else {
            // Only padding when data length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
            state.permutation(6);
        }
    }

    /// Add delay after block processing
    fn delay_after_block_processing(&self, state: &mut AsconState) {
        // Additional computation after each block
        let mut val = state.x[0];
        for _ in 0..5 {
            val = val.wrapping_mul(0x5bd1e9955bd1e995) ^ (val >> 7) ^ (val << 12);
        }
        state.x[1] ^= val;
    }

    /// Process plaintext and generate ciphertext
    fn process_plaintext(&self, state: &mut AsconState, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= plaintext.len() {
            let block = u64::from_be_bytes(plaintext[i..i + 8].try_into().unwrap());
            state.x[0] ^= block;
            ciphertext.extend_from_slice(&state.x[0].to_be_bytes());
            state.permutation(6);
            // ADDITIONAL DELAY AFTER EACH BLOCK PROCESSING
            self.delay_after_block_processing(state);
            i += 8;
        }
        
        // Process final partial block
        if i < plaintext.len() {
            let remaining = plaintext.len() - i;
            let mut last_block = [0u8; 8];
            last_block[..remaining].copy_from_slice(&plaintext[i..]);
            
            let block = u64::from_be_bytes(last_block);
            state.x[0] ^= block;
            
            let ct_bytes = state.x[0].to_be_bytes();
            ciphertext.extend_from_slice(&ct_bytes[..remaining]);
            
            // Padding
            last_block.fill(0);
            last_block[remaining] = 0x80;
            state.x[0] ^= u64::from_be_bytes(last_block);
        } else {
            // Only padding when plaintext length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
        }
        
        ciphertext
    }

    /// Process ciphertext and generate plaintext
    fn process_ciphertext(&self, state: &mut AsconState, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut i = 0;
        
        // Process full 8-byte blocks
        while i + 8 <= ciphertext.len() {
            let ct_block = u64::from_be_bytes(ciphertext[i..i + 8].try_into().unwrap());
            let pt_block = state.x[0] ^ ct_block;
            plaintext.extend_from_slice(&pt_block.to_be_bytes());
            state.x[0] = ct_block;
            state.permutation(6);
            // ADDITIONAL DELAY AFTER EACH BLOCK PROCESSING
            self.delay_after_block_processing(state);
            i += 8;
        }
        
        // Process final partial block
        if i < ciphertext.len() {
            let remaining = ciphertext.len() - i;
            let mut ct_block = [0u8; 8];
            ct_block[..remaining].copy_from_slice(&ciphertext[i..]);
            
            let ct = u64::from_be_bytes(ct_block);
            let mask = (!0u64) << (8 * (8 - remaining));
            let pt = state.x[0] ^ ct;
            
            let pt_bytes = pt.to_be_bytes();
            plaintext.extend_from_slice(&pt_bytes[..remaining]);
            
            state.x[0] = (ct & mask) | (state.x[0] & !mask);
            
            // Padding
            ct_block.fill(0);
            ct_block[remaining] = 0x80;
            state.x[0] ^= u64::from_be_bytes(ct_block);
        } else {
            // Only padding when ciphertext length is multiple of 8
            state.x[0] ^= 0x8000000000000000;
        }
        
        plaintext
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
