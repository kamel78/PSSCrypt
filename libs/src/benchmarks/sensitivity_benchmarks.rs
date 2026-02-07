use std::{arch::x86_64::_mm_xor_si128, io};

use rand::{rngs::StdRng, Rng, SeedableRng};
use crate::{gcm::aes_gcm::as_m128i, aes_ciphers::CipherName, pss::psscrypt::PSSCrypt};
  pub enum TestParam { KEY,IV }


//  Benchmarking  sensivity to bit alteration of recovered authentication tag scheme with respect to ciphertext alterations

pub fn tag_sensitivity(){
    fn hamming_diffrence(source: u128, dest: u128) -> u128 {    
        (source ^ dest).count_ones() as u128       
    }    
    println!("Warning: the next computation may take a long time depending on the configuration parameters.");
    println!("The result of this computation provides the statistical distribution of sensitivity with respect to each experiment: one-, two-, four-, and eight-bit flipping.");
    println!("Enter 'N' to cancel, or any other key to continue:");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    if input.trim() == "N" {return;};
    println!("{}",input);
    let plain_size = 1024 * 100  ;
    let plain_count = 5;
    let keys_count = 1000;
    let one_flips_trials = 10; 
    let two_and_four_flips_trials = 100; 
    println!("plain-text messages count :{}",plain_count);
    println!("plain-text messages size :{} byte",plain_size);
    println!("Keys count :{} byte",keys_count);
    println!("One-bit flipls trials :{} byte",one_flips_trials);
    println!("Two-bit flipls trials :{} byte",two_and_four_flips_trials);
    println!("Four-bit flipls trials :{} byte",two_and_four_flips_trials);
    println!("Eight-bit flipls trials :{} byte",two_and_four_flips_trials);
    let data_size = plain_size * plain_count;
    let mut data = Vec::<u8>::new();
    let seed: [u8; 32] = [0xAB; 32];                // can be any fixed byte pattern
    let mut rng = StdRng::from_seed(seed);
    data.resize_with(data_size, || rng.random::<u8>());    
    let mut keys :[u128;1000] =[0;1000];
    for i in 0..keys_count { keys[i] = rand::rng().random::<u128>();}    
    let mut dist_one_bit :[u128;128]= [0;128]; 
    let mut dist_two_bit :[u128;128]= [0;128]; 
    let mut dist_four_bit :[u128;128]= [0;128];

    // Experiments on one bit flipping
    let mut num_exp: u64 =0;
    for i in 0..plain_count{
                    let mut core = PSSCrypt::new(&data[i* plain_size..],plain_size, CipherName::AES128, false);
                    for k in keys{      let iv = rand::rng().random::<u128>();
                                              core.set_key_materials(&[k,k], iv, CipherName::AES128);  
                                              let tag = core.encrypt();
                                              for _ in 0..one_flips_trials{                                                
                                                let flip_pos = rng.random_range(10..core.internal.len());
                                                let flip_idx = rng.random_range(1..128);
                                                let save = core.internal[flip_pos];
                                                core.internal[flip_pos] = unsafe { _mm_xor_si128(core.internal[flip_pos] , as_m128i(1 << flip_idx)) };
                                                let recovered_iv = core.decrypt(tag, true);
                                                core.internal[flip_pos] = save;
                                                let distance = hamming_diffrence(iv,recovered_iv);
                                                dist_one_bit[distance as usize] = dist_one_bit [distance as usize]+1;
                                                num_exp =num_exp +1;
                                              }                            
                                        }}
    println!("One bit flipping results :{} experiment ",num_exp);
    for i in 0..128 {println!("{}",dist_one_bit[i] as f32 /(num_exp)as f32)}
    // Experiments on two bit flipping
    let mut num_exp: u64 =0;
    for i in 0..plain_count{
                        let mut core = PSSCrypt::new(&data[i* plain_size..],plain_size, CipherName::AES128, false);
                        for k in keys{     
                       let iv = rand::rng().random::<u128>();
                                              core.set_key_materials(&[k,k], iv, CipherName::AES128);  
                                              let tag = core.encrypt();
                                              for _ in 0..two_and_four_flips_trials{
                                                let flip_pos1 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save1 = core.internal[flip_pos1];
                                                core.internal[flip_pos1] = unsafe { _mm_xor_si128(core.internal[flip_pos1] , as_m128i(1 << flip_idx)) };
                                                let flip_pos2 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save2 = core.internal[flip_pos2];
                                                core.internal[flip_pos2] = unsafe { _mm_xor_si128(core.internal[flip_pos2] , as_m128i(1 << flip_idx)) };                                                
                                                let recovered_iv = core.decrypt(tag, true);
                                                core.internal[flip_pos1] = save1;
                                                core.internal[flip_pos2] = save2;
                                                let distance = hamming_diffrence(iv,recovered_iv);
                                                dist_two_bit[distance as usize] = dist_two_bit [distance as usize]+1;
                                                num_exp =num_exp +1;
                                              }                            
                                        }                                        

                            }   
    println!("Two bit flipping results : ");
    for i in 0..128 {println!("{}",dist_two_bit[i] as f32 /(num_exp)as f32)}    
    let mut num_exp: u64 =0;
    // // Experiments on four bit flipping
    for i in 0..plain_count{
                    let mut core = PSSCrypt::new(&data[i* plain_size..],plain_size, CipherName::AES128, false);
                    for k in keys{      let iv = rand::rng().random::<u128>();
                                              core.set_key_materials(&[k,k], iv, CipherName::AES128);  
                                              let tag = core.encrypt();
                                              for _ in 0..two_and_four_flips_trials{                                                 
                                                let flip_pos1 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save1 = core.internal[flip_pos1];
                                                core.internal[flip_pos1] = unsafe { _mm_xor_si128(core.internal[flip_pos1] , as_m128i(1 << flip_idx)) };
                                                let flip_pos2 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save2 = core.internal[flip_pos2];
                                                core.internal[flip_pos2] = unsafe { _mm_xor_si128(core.internal[flip_pos2] , as_m128i(1 << flip_idx)) };
                                                let flip_pos3 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save3 = core.internal[flip_pos3];
                                                core.internal[flip_pos3] = unsafe { _mm_xor_si128(core.internal[flip_pos3] , as_m128i(1 << flip_idx)) };
                                                let flip_pos4 = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(0..127);
                                                let save4 = core.internal[flip_pos4];
                                                core.internal[flip_pos4] = unsafe { _mm_xor_si128(core.internal[flip_pos4] , as_m128i(1 << flip_idx)) };                                                
                                                let recovered_iv = core.decrypt(tag, true);
                                                core.internal[flip_pos1] = save1;
                                                core.internal[flip_pos2] = save2;
                                                core.internal[flip_pos3] = save3;
                                                core.internal[flip_pos4] = save4;
                                                let distance =hamming_diffrence(iv,recovered_iv);
                                                dist_four_bit[distance as usize] = dist_four_bit [distance as usize]+1;
                                                num_exp =num_exp +1;
                                              }                            
                                        }                                        
                            }  
    println!("Four bit flipping results : ");
    for i in 0..128 {println!("{}",dist_four_bit[i] as f32 /(num_exp)as f32)}    
     let mut num_exp: u64 =0;
    // // Experiments on eight bit flipping
    for i in 0..plain_count{
                    let mut core = PSSCrypt::new(&data[i* plain_size..],plain_size, CipherName::AES128, false);
                    for k in keys{      let iv = rand::rng().random::<u128>();
                                              core.set_key_materials(&[k,k], iv, CipherName::AES128);  
                                              let tag = core.encrypt();
                                              for _ in 0..two_and_four_flips_trials{                                                 
                                                let flip_pos = rng.random_range(0..core.internal.len());
                                                let flip_idx = rng.random_range(1..32);
                                                let abyte =rand::rng().random::<u8>();
                                                let save1 = core.internal[flip_pos];
                                                core.internal[flip_pos] = unsafe { _mm_xor_si128(core.internal[flip_pos] , as_m128i((abyte << flip_idx).into())) };                                                
                                                let recovered_iv = core.decrypt(tag, true);
                                                core.internal[flip_pos] = save1;
                                                let distance =hamming_diffrence(iv,recovered_iv);
                                                dist_four_bit[distance as usize] = dist_four_bit [distance as usize]+1;
                                                num_exp =num_exp +1;
                                              }                            
                                        }                                        
                            }  
    println!("eight bit flipping results : ");
    for i in 0..128 {println!("{}",dist_four_bit[i] as f32 /(num_exp)as f32)}                                                                    
    }                            
                            
//  Benchmarking  sensivity to bit alteration of the proposed encryption scheme with respect to KEY/IV alterations

pub fn sensitivity_bench(param :TestParam){
    fn bit_distances(t_size:usize,source: &[u8], dest: &[u8]) -> f32 {    
        let mut count: u128 = 0;
        for i in 0..t_size {
            count += (source[i] ^ dest[i]).count_ones() as u128;
        }
        count as f32 / (source.len() as f32 * 8.0)
    }
    let t_size :usize =10240;
    let mut data = Vec::<u8>::new();
    let mut rng = rand::rng();
    data.resize_with(t_size, || rng.random::<u8>());    
    let key = rand::rng().random::<u128>();    
    let iv = rand::rng().random::<u128>();                
    let mut rng: rand::prelude::ThreadRng = rand::rng();
    for i in 0..128{
                let mut diff :f32 = 0.0;
                for _ in 0..1000{  
                            data.resize_with(t_size, || rng.random::<u8>());    
                            let mut st1 = PSSCrypt::new(&data,t_size, CipherName::AES128, false);                        
                            let mut st = PSSCrypt::new(&data,t_size, CipherName::AES128, false);
                            st.set_key_materials(&[key,key], iv,CipherName::AES128);                            
                            st.encrypt();
                            let res1 = st.encrypted_bytes();
                            let key1 ;
                            let iv1 ;
                            match  param {
                                TestParam::KEY => { key1 = key ^  ( 1<< i);
                                                    iv1 = iv;}
                                TestParam::IV => {  key1 = key;
                                                    iv1 = iv ^ (1 << i);},
                            }                                                                                    
                            st1.set_key_materials(&[key1,key1], iv1,CipherName::AES128);
                            st1.encrypt();
                            let res2 = st1.encrypted_bytes();        
                            diff = diff + bit_distances(t_size, res1, res2);
                        }
                println!("{} %",diff/(1000.0));
        }
}