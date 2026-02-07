use std::{io, time::Instant};
use libraries::{aes_ciphers::aes::AES128, benchmarks::{ microbench_aes::microbench_aes, scalability_benchmarks::*, 
                             sensitivity_benchmarks::{TestParam, sensitivity_bench, tag_sensitivity}, 
                             time_benchmarks::*}, params_generation::{galois_arithmetic::GF128, generate_params::gen_params}};
fn test_speed(){
    let key128 = GF128::random().to_u128();
    let aes128 = AES128::new(&[key128]);
    let mut plain = GF128::random();    
    let plain1 = GF128::random();    
    let iteration =100000;
    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        plain = aes128.encrypt_block(plain.to_u128()).into();
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg1 = avg / (iteration as f32);
    println!("   Average encryption time (AES128): {:.2} ns ", avg1);
    let mut avg :f32 = 0.0;
    for _ in 0..iteration{
        let start = Instant::now();
        plain = plain.multiply(&plain1);
        let duration = start.elapsed();
        avg = avg + (duration.as_nanos() as f32);
    }
    let avg1 = avg / (iteration as f32);
    println!("   Multiplication time (AES128): {:.2} ns ", avg1);
}                             
fn main(){
    
    test_speed();
      loop {    println!("============================================================================");
                println!("Please enter a choice (1, 2, or 3) for the following routines, or 4 to exit:"); 
                println!("Please run in '--release' mode for accurate results.");
                println!("============================================================================");
                println!("(1)- Runtime bench-marking of several implemented schemes in 128bit level.");
                println!("(2)- Runtime bench-marking of several implemented schemes in 1256bit level.");
                println!("(3)- Key and IV sensitivity benchmarking.");
                println!("(4)- Tag and authentication sensitivity benchmarking.");
                println!("(5)- Runtime scaling from 128bit to 256bit level.");
                println!("(6)- Microbenchmark AES 128/256.");
                println!("(7)- Generate and lis parameters for the proposed scheme over GF(128).");
                println!("Enter 8 to leave ...");
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let choice1: u32 = match input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input. Please enter a number.");
                        return;
                    }
                };
                if choice1 == 8 {break;}
                match  choice1 { 1=> {  bench_aes_gcm_throughput();
                                        bench_aes_gcm_latency();
                                        bench_aes_ccm_throughput();
                                        bench_aes_ccm_latency();
                                        bench_aes_pss_latency();
                                        bench_aes_pss_throughput();
                                        bench_aes_ocb_throughput();
                                        bench_aes_ocb_latency();
                                        bench_ascon_throughput();
                                        bench_ascon_latency();
                                        bench_sparkle_throughput();
                                        bench_sparkle_latency();
                                        bench_giftcofb_throughput();
                                        bench_giftcofb_latency();
                                     }
                                 2=> {  bench_aes_gcm_256_throughput();
                                        bench_aes_gcm_256_latency();
                                        bench_aes_ccm_256_throughput();
                                        bench_aes_ccm_256_latency();
                                        bench_aes_pss_256_latency();
                                        bench_aes_pss_256_throughput();
                                        bench_aes_ocb_256_throughput();
                                        bench_aes_ocb_256_latency();
                                     }                              
                                 3=>{   sensitivity_bench(TestParam::KEY);
                                        sensitivity_bench(TestParam::IV)} ,
                                 4=>{   tag_sensitivity()   },
                                 5=> {  bench_aes_gcm_scaling();
                                        bench_aes_ccm_scaling();
                                        bench_aes_ocb_scaling();
                                        bench_aes_pss_scaling();
                                        bench_sparkle_scaling();
                                     }                        
                                 6=>{   microbench_aes()   },
                                 7=>{   gen_params(4)   },

                                 _ =>{}       
                                }
                }

      
}
