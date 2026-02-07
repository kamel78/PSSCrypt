use std::time::Instant;

use crate::{aes_ciphers::CipherName, additional_ae::{ascon_ae::Ascon128, gift_cofb::GiftCofb, sparkle_ae::Schwaemm128}, ccm::{aes_ccm::AesCcm, aes_ccm_256::AesCcm256}, gcm::{aes_gcm::AesGcm, aes_gcm_256::AesGcm256}, ocb::{aes_ocb::AesOcb, aes_ocb_256::AesOcb256}, pss::psscrypt::PSSCrypt};

pub fn throughput_mbs(size: usize, nanos: u128) -> f64 {
    if nanos == 0 {return 0.0;}
    ((size as f64) * 8.0 / nanos as f64) * 1_000.0
}

// Benchmarking Latency / Throughput for the proposed scheme/AES-GCM/AES-CCM/AES-OCB for both 128bit and 256bit instances 

pub fn bench_aes_gcm_latency() {
    println!("\n=== AES-GCM-128 Latency Benchmark (10KB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let ccm = AesGcm::new(key);    
    // Warmup
    for _ in 0..10 {    let _ = ccm.encrypt(&nonce, &plaintext, aad);   }    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad);
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());        
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad);
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_ccm_latency() {
    println!("\n=== AES-CCM-128 Latency Benchmark (10KB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ccm = AesCcm::new(key);   
    // Warmup
    for _ in 0..10 {    let _ = ccm.encrypt(&nonce, &plaintext, aad, tag_len);}    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());                                
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_ccm_throughput() {
    println!("\n=== AES-CCM-128 Throughput Benchmark (1Gb) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ccm = AesCcm::new(key);
    // Warmup
    for _ in 0..10 {    let _ = ccm.encrypt(&nonce, &plaintext, aad, tag_len);  }   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());                                
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_ccm_256_latency() {
    println!("\n=== AES-CCM-256 Latency Benchmark (10KB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ccm = AesCcm256::new(&[key1,key2]);   
    // Warmup
    for _ in 0..10 {    let _ = ccm.encrypt(&nonce, &plaintext, aad, tag_len);}    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());                                
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_ccm_256_throughput() {
    println!("\n=== AES-CCM-256 Throughput Benchmark (1Gb) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ccm = AesCcm256::new(&[key1,key2]);
    // Warmup
    for _ in 0..10 {    let _ = ccm.encrypt(&nonce, &plaintext, aad, tag_len);  }   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());                                
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_gcm_throughput() {
    println!("\n=== AES-GCM-128 Throughput Benchmark (1GB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let ccm = AesGcm::new(key);
    // Warmup
    for _ in 0..10 {let _ = ccm.encrypt(&nonce, &plaintext, aad);}   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad);
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());   
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ccm.encrypt(&nonce, &plaintext, aad);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ccm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_gcm_256_latency() {
    println!("\n=== AES-GCM-256 Latency Benchmark (10KB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let gcm = AesGcm256::new(&[key1,key2]);    
    // Warmup
    for _ in 0..10 {    let _ = gcm.encrypt(&nonce, &plaintext, aad);   }    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = gcm.encrypt(&nonce, &plaintext, aad);
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());        
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = gcm.encrypt(&nonce, &plaintext, aad);
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = gcm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_gcm_256_throughput() {
    println!("\n=== AES-GCM-256 Throughput Benchmark (1GB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let gcm = AesGcm256::new(&[key1,key2]);
    // Warmup
    for _ in 0..10 {let _ = gcm.encrypt(&nonce, &plaintext, aad);}   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = gcm.encrypt(&nonce, &plaintext, aad);
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());   
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = gcm.encrypt(&nonce, &plaintext, aad);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = gcm.decrypt(&nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_pss_latency() {
    println!("\n=== PSS-128 Latency Benchmark (10KB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let iv = 0x0123456789abcdef0123456789abcdef;    
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];    
    let mut pss = PSSCrypt::new(&plaintext,size,  CipherName::AES128,false);
    pss.set_key_materials(&[key,key], iv, CipherName::AES128);
    // Warmup
    for _ in 0..10 {    let _ = pss.encrypt();}    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.encrypt();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());                                        
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
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.decrypt(0,true);
                                let duration = start.elapsed();
                                decrypt_latencies.push(duration.as_nanos());                                        
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

pub fn bench_aes_pss_256_latency() {
    println!("\n=== PSS-256 Latency Benchmark (10KB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let iv = 0x0123456789abcdef0123456789abcdef;    
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];    
    let mut pss = PSSCrypt::new(&plaintext,size,  CipherName::AES256,false);
    pss.set_key_materials(&[key1,key2], iv, CipherName::AES256);
    // Warmup
    for _ in 0..10 {    let _ = pss.encrypt();}    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.encrypt();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());                                        
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
    let mut decrypt_latencies = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.decrypt(0,true);
                                let duration = start.elapsed();
                                decrypt_latencies.push(duration.as_nanos());                                        
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

pub fn bench_aes_pss_throughput() {
    println!("\n=== PSS-128 Throughput Benchmark (1GB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let iv = 0x0123456789abcdef0123456789abcdef;    
    let size = 1024 * 1024 * 100;  
    let plaintext = vec![0x42u8; size];    
    let mut pss = PSSCrypt::new(&plaintext,size,  CipherName::AES128,false);
    pss.set_key_materials(&[key,key], iv, CipherName::AES128);
    // Warmup
    for _ in 0..10 {    let _ = pss.encrypt();}   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.encrypt();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());                
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
    let mut decrypt_throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.decrypt(0,true);
                                let duration = start.elapsed();
                                decrypt_throughputs.push(duration.as_nanos());
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

pub fn bench_aes_pss_256_throughput() {
    println!("\n=== PSS-256 Throughput Benchmark (1GB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let iv = 0x0123456789abcdef0123456789abcdef;    
    let size = 1024 * 1024 * 100; // 10KB
    let plaintext = vec![0x42u8; size];    
    let mut pss = PSSCrypt::new(&plaintext,size,  CipherName::AES256,false);
    pss.set_key_materials(&[key,key], iv, CipherName::AES256);
    // Warmup
    for _ in 0..10 {    let _ = pss.encrypt();}   
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.encrypt();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());                
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
    let mut decrypt_throughputs = Vec::with_capacity(iterations);    
    for _ in 0..iterations {    let start = Instant::now();
                                let _ = pss.decrypt(0,true);
                                let duration = start.elapsed();
                                decrypt_throughputs.push(duration.as_nanos());
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

pub fn bench_aes_ocb_throughput() {
    println!("\n=== AES-OCB-128 Throughput Benchmark (10MB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = b"ABCDEFGHIJKL"; // 12 bytes
    let size = 1024 * 100 * 1024;
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ocb = AesOcb::new(key);
    // Warmup
    for _ in 0..10 {
        let _ = ocb.encrypt(nonce, &plaintext, aad, tag_len);
    }
    // Measure encryption throughput
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
                            }

    // Calculate statistics
    throughputs.sort_unstable_by(|a, b| b.cmp(a));
    let min = throughputs[0];
    let max = throughputs[iterations - 1];
    let median = throughputs[iterations / 2];
    let p95 = throughputs[(iterations * 95) / 100];
    let p99 = throughputs[(iterations * 99) / 100];
    let avg: u128 = throughputs.iter().sum::<u128>() / iterations as u128;

    println!(" Encryption (10MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
    println!("   Median:  {} ns ({:.2} Mb/s)", median, throughput_mbs(size, median));
    println!("   Average: {} ns ({:.2} Mb/s)", avg, throughput_mbs(size, avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));

    // Measure decryption throughput
    let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ocb.decrypt(nonce, &ciphertext, aad, &tag).unwrap();
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

    println!("\n Decryption (10MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", dec_min, throughput_mbs(size, dec_min));
    println!("   Median:  {} ns ({:.2} Mb/s)", dec_median, throughput_mbs(size, dec_median));
    println!("   Average: {} ns ({:.2} Mb/s)", dec_avg, throughput_mbs(size, dec_avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", dec_p95, throughput_mbs(size, dec_p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", dec_p99, throughput_mbs(size, dec_p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", dec_max, throughput_mbs(size, dec_max));
}

pub fn bench_aes_ocb_latency() {
    println!("\n=== AES-OCB-128 Latency Benchmark (10KB) ===\n");
    let key = 0x0123456789abcdef0123456789abcdef;
    let nonce = b"ABCDEFGHIJKL";
    let size = 10 * 1024; //10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ocb = AesOcb::new(key);
    // Warmup
    for _ in 0..10 {    let _ = ocb.encrypt(nonce, &plaintext, aad, tag_len);}
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ocb.decrypt(nonce, &ciphertext, aad, &tag).unwrap();
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

pub fn bench_aes_ocb_256_throughput() {
    println!("\n=== AES-OCB-256 Throughput Benchmark (10MB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = b"ABCDEFGHIJKL"; // 12 bytes
    let size = 1024 * 100 * 1024;
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ocb = AesOcb256::new(&[key1,key2]);
    // Warmup
    for _ in 0..10 {
        let _ = ocb.encrypt(nonce, &plaintext, aad, tag_len);
    }
    // Measure encryption throughput
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                throughputs.push(duration.as_nanos());
                                // Prevent optimization
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
                            }

    // Calculate statistics
    throughputs.sort_unstable_by(|a, b| b.cmp(a));
    let min = throughputs[0];
    let max = throughputs[iterations - 1];
    let median = throughputs[iterations / 2];
    let p95 = throughputs[(iterations * 95) / 100];
    let p99 = throughputs[(iterations * 99) / 100];
    let avg: u128 = throughputs.iter().sum::<u128>() / iterations as u128;

    println!(" Encryption (10MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
    println!("   Median:  {} ns ({:.2} Mb/s)", median, throughput_mbs(size, median));
    println!("   Average: {} ns ({:.2} Mb/s)", avg, throughput_mbs(size, avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));

    // Measure decryption throughput
    let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ocb.decrypt(nonce, &ciphertext, aad, &tag).unwrap();
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

    println!("\n Decryption (10MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", dec_min, throughput_mbs(size, dec_min));
    println!("   Median:  {} ns ({:.2} Mb/s)", dec_median, throughput_mbs(size, dec_median));
    println!("   Average: {} ns ({:.2} Mb/s)", dec_avg, throughput_mbs(size, dec_avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", dec_p95, throughput_mbs(size, dec_p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", dec_p99, throughput_mbs(size, dec_p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", dec_max, throughput_mbs(size, dec_max));
}

pub fn bench_aes_ocb_256_latency() {
    println!("\n=== AES-OCB-256 Latency Benchmark (10KB) ===\n");
    let key1 = 0x0123456789abcdef0123456789abcdef;
    let key2 = 0xfedcba9876543210fedcba9876543210;
    let nonce = b"ABCDEFGHIJKL";
    let size = 10 * 1024;
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let tag_len = 16;
    let ocb = AesOcb256::new(&[key1,key2]);
    // Warmup
    for _ in 0..10 {    let _ = ocb.encrypt(nonce, &plaintext, aad, tag_len);}
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
                                let duration = start.elapsed();
                                latencies.push(duration.as_nanos());
                                std::hint::black_box(&ciphertext);
                                std::hint::black_box(&tag);
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
    let (ciphertext, tag) = ocb.encrypt(nonce, &plaintext, aad, tag_len).unwrap();
    let mut decrypt_latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {    let start = Instant::now();
                                let plaintext_decrypted = ocb.decrypt(nonce, &ciphertext, aad, &tag).unwrap();
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


/// Benchmark Ascon-128 throughput
pub fn bench_ascon_throughput() {
    use std::time::Instant;
    
    println!("\n=== Ascon-128 Throughput Benchmark (1GB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 1024 * 100 * 1024; // 100 MB (adjusted for reasonable benchmark time)
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let ascon = Ascon128::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = ascon.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
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
    
    println!(" Encryption (100MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
    println!("   Median:  {} ns ({:.2} Mb/s)", median, throughput_mbs(size, median));
    println!("   Average: {} ns ({:.2} Mb/s)", avg, throughput_mbs(size, avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));
    
    // Measure decryption latency
    let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = ascon.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
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
    
    println!("\n Decryption (100MB):");
    println!("   Min:     {} ns ({:.2} Mb/s)", dec_min, throughput_mbs(size, dec_min));
    println!("   Median:  {} ns ({:.2} Mb/s)", dec_median, throughput_mbs(size, dec_median));
    println!("   Average: {} ns ({:.2} Mb/s)", dec_avg, throughput_mbs(size, dec_avg));
    println!("   P95:     {} ns ({:.2} Mb/s)", dec_p95, throughput_mbs(size, dec_p95));
    println!("   P99:     {} ns ({:.2} Mb/s)", dec_p99, throughput_mbs(size, dec_p99));
    println!("   Max:     {} ns ({:.2} Mb/s)", dec_max, throughput_mbs(size, dec_max));
}

/// Benchmark Schwaemm256-128 throughput
pub fn bench_sparkle_throughput() {
    println!("\n=== Schwaemm256-128 (Sparkle) Throughput Benchmark (1GB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 1024 * 100 * 1024; 
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let sparkle = Schwaemm128::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = sparkle.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = sparkle.encrypt(&nonce, aad, &plaintext);
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
    let ciphertext_with_tag = sparkle.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = sparkle.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
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

/// Benchmark Schwaemm256-128 latency
pub fn bench_sparkle_latency() {
    println!("\n=== Schwaemm256-128 (Sparkle) Latency Benchmark (10KB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let sparkle = Schwaemm128::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = sparkle.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = sparkle.encrypt(&nonce, aad, &plaintext);
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
    let ciphertext_with_tag = sparkle.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = sparkle.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
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


/// Benchmark GIFT-COFB throughput
pub fn bench_giftcofb_throughput() {
    println!("\n=== GIFT-COFB Throughput Benchmark (100MB) ===\n");
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 1024 * 1024; // 100 MB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let giftcofb = GiftCofb::new(key);
    // Warmup
    for _ in 0..10 {
        let _ = giftcofb.encrypt(&nonce, aad, &plaintext);
    }
    // Measure encryption throughput
    let iterations = 10;
    let mut throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = giftcofb.encrypt(&nonce, aad, &plaintext);
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
    println!(" Encryption (100MB):");
    println!(" Min: {} ns ({:.2} Mb/s)", min, throughput_mbs(size, min));
    println!(
        " Median: {} ns ({:.2} Mb/s)",
        median,
        throughput_mbs(size, median)
    );
    println!(
        " Average: {} ns ({:.2} Mb/s)",
        avg,
        throughput_mbs(size, avg)
    );
    println!(" P95: {} ns ({:.2} Mb/s)", p95, throughput_mbs(size, p95));
    println!(" P99: {} ns ({:.2} Mb/s)", p99, throughput_mbs(size, p99));
    println!(" Max: {} ns ({:.2} Mb/s)", max, throughput_mbs(size, max));
    // Measure decryption throughput
    let ciphertext_with_tag = giftcofb.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_throughputs = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = giftcofb.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
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
    println!("\n Decryption (100MB):");
    println!(
        " Min: {} ns ({:.2} Mb/s)",
        dec_min,
        throughput_mbs(size, dec_min)
    );
    println!(
        " Median: {} ns ({:.2} Mb/s)",
        dec_median,
        throughput_mbs(size, dec_median)
    );
    println!(
        " Average: {} ns ({:.2} Mb/s)",
        dec_avg,
        throughput_mbs(size, dec_avg)
    );
    println!(
        " P95: {} ns ({:.2} Mb/s)",
        dec_p95,
        throughput_mbs(size, dec_p95)
    );
    println!(
        " P99: {} ns ({:.2} Mb/s)",
        dec_p99,
        throughput_mbs(size, dec_p99)
    );
    println!(
        " Max: {} ns ({:.2} Mb/s)",
        dec_max,
        throughput_mbs(size, dec_max)
    );
}

pub fn bench_giftcofb_latency() {
    println!("\n=== GIFT-COFB Latency Benchmark (Small Messages) ===\n");
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 1024; // 1KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    let giftcofb = GiftCofb::new(key);
    // Warmup
    for _ in 0..100 {
        let _ = giftcofb.encrypt(&nonce, aad, &plaintext);
    }
    // Measure
    let iterations = 1000;
    let mut latencies = Vec::new();
    for _ in 0..iterations {
        let start = Instant::now();
        let ct = giftcofb.encrypt(&nonce, aad, &plaintext);
        latencies.push(start.elapsed().as_nanos());
        std::hint::black_box(&ct);
    }
    latencies.sort_unstable();
    let min = latencies[0];
    let median = latencies[iterations / 2];
    let p95 = latencies[(iterations * 95) / 100];
    let p99 = latencies[(iterations * 99) / 100];
    let avg: u128 = latencies.iter().sum::<u128>() / iterations as u128;
    println!(" Encryption (1KB) Latency:");
    println!(" Min: {:.2} µs", min as f64 / 1000.0);
    println!(" Median: {:.2} µs", median as f64 / 1000.0);
    println!(" Average: {:.2} µs", avg as f64 / 1000.0);
    println!(" P95: {:.2} µs", p95 as f64 / 1000.0);
    println!(" P99: {:.2} µs", p99 as f64 / 1000.0);
}



/// Benchmark Ascon-128 latency
pub fn bench_ascon_latency() {
    use std::time::Instant;
    
    println!("\n=== Ascon-128 Latency Benchmark (10KB) ===\n");
    
    let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let size = 10 * 1024; // 10KB
    let plaintext = vec![0x42u8; size];
    let aad = b"Additional authenticated data";
    
    let ascon = Ascon128::new(key);
    
    // Warmup
    for _ in 0..10 {
        let _ = ascon.encrypt(&nonce, aad, &plaintext);
    }
    
    // Measure encryption latency
    let iterations = 1000;
    let mut latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
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
    let ciphertext_with_tag = ascon.encrypt(&nonce, aad, &plaintext);
    let mut decrypt_latencies = Vec::with_capacity(iterations);
    
    for _ in 0..iterations {
        let start = Instant::now();
        let plaintext_decrypted = ascon.decrypt(&nonce, aad, &ciphertext_with_tag).unwrap();
        let duration = start.elapsed();
        decrypt_latencies.push(duration.as_nanos());
        
        std::hint::black_box(&plaintext_decrypted);
    }
    
    decrypt_latencies.sort_unstable();
    let dec_min = decrypt_latencies[0];
    let dec_median = decrypt_latencies[iterations / 2];
    let dec_avg: u128 = decrypt_latencies.iter().sum::<u128>() / iterations as u128;
    let dec_p95 = decrypt_latencies[(iterations * 95) / 100];
    // let dec_p99 = decrypt_latencies[(iterations * 99) / 100];
    let dec_max = decrypt_latencies[iterations - 1];
    
    println!("\n Decryption (10KB) Latency:");
    println!("   Min:     {:.2} µs", dec_min as f64 / 1000.0);
    println!("   Median:  {:.2} µs", dec_median as f64 / 1000.0);
    println!("   Average: {:.2} µs", dec_avg as f64 / 1000.0);
    println!("   P95:     {:.2} µs", dec_p95 as f64 / 1000.0);
    println!("   P99:     {:.2} µs", p99 as f64 / 1000.0);
    println!("   Max:     {:.2} µs", dec_max as f64 / 1000.0);
}

