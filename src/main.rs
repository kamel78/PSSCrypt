use std::io;
use libraries::benchmarks::{ microbench_aes::microbench_aes, scalability_benchmarks::*, 
                             sensitivity_benchmarks::{sensitivity_bench, tag_sensitivity, TestParam}, 
                             time_benchmarks::*};

fn main(){
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
                println!("Enter 7 to leave ...");
                let mut input = String::new();
                io::stdin().read_line(&mut input).expect("Failed to read line");
                let choice1: u32 = match input.trim().parse() {
                    Ok(num) => num,
                    Err(_) => {
                        println!("Invalid input. Please enter a number.");
                        return;
                    }
                };
                if choice1 == 7 {break;}
                match  choice1 { 1=> {  bench_aes_gcm_throughput();
                                        bench_aes_gcm_latency();
                                        bench_aes_ccm_throughput();
                                        bench_aes_ccm_latency();
                                        bench_aes_pss_latency();
                                        bench_aes_pss_throughput();
                                        bench_aes_ocb_throughput();
                                        bench_aes_ocb_latency();
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
                                     }                        
                                 6=>{   microbench_aes()   },

                                 _ =>{}       
                                }
                }
}