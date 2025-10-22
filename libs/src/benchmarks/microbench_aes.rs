use std::time::Instant;

use rand::Rng;

use crate::aes_ciphers::{aes::AES128, aes256::AES256};


//  Microbench to compare elementary timining diffrence between AES128 and AES256 (encryption / decryption)
pub fn microbench_aes(){
    let key128 = rand::rng().random::<u128>();    
    let key256_1 = rand::rng().random::<u128>();    
    let key256_2 = rand::rng().random::<u128>();    
    let aes128 = AES128::new(&[key128]);
    let aes256 = AES256::new(&[key256_1,key256_2]);
    let plain = rand::rng().random::<u128>();    
    let iteration =100000;
    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        let _ = aes128.encrypt_block(plain);
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg1 = avg / (iteration as f32);
    println!("   Average encryption time (AES128): {:.2} ns ", avg1);

    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        let _ = aes256.encrypt_block(plain);
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg2 = avg / (iteration as f32);
    println!("   Average encryption time (AES256): {:.2} ns ", avg2);
    println!("   Delta cost : {:.2} % ", ((avg2-avg1)/avg1)*100.0);

    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        let _ = aes128.decrypt_block(plain);
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg1 = avg / (iteration as f32);
    println!("   Average decryption time (AES128): {:.2} ns ", avg1);

    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        let _ = aes256.decrypt_block(plain);
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg2 = avg / (iteration as f32);
    println!("   Average decryption time (AES256): {:.2} ns ", avg2);
    println!("   Delta cost : {:.2} % ", ((avg2-avg1)/avg1)*100.0);
        
}
