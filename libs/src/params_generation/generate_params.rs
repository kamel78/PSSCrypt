use sha2::{Sha256,Digest};

use crate::params_generation::galois_arithmetic::{matrix::GF128Matrix, vector::GF128Vector, GF128};

// Ascon state representation as five 64-bit words
#[derive(Clone)]
struct AsconDeriver { state: [u64; 5] }

impl AsconDeriver {
    fn new() -> Self {
        Self { state: [0u64; 5] }
    }
    // XOR data into the first r bits of the state
    fn absorb(&mut self, data: &[u8], rate: usize) {
        let rate_bytes = rate / 8;
        let mut padded = [0u8; 40]; // 320 bits = 40 bytes        
        // Copy data into the first rate_bytes
        let copy_len = std::cmp::min(data.len(), rate_bytes);
        padded[..copy_len].copy_from_slice(&data[..copy_len]);        
        // XOR with state
        for (i, chunk) in padded.chunks(8).enumerate() {
            if i < 5 {
                let mut bytes = [0u8; 8];
                bytes[..chunk.len()].copy_from_slice(chunk);
                self.state[i] ^= u64::from_le_bytes(bytes);
            }
        }
    }
    // Extract the first m bits as bytes
    fn squeeze(&self, m: usize) -> [u8; 16] {
        let mut result = [0u8; 16];
        let byte_len = std::cmp::min((m + 7) / 8, 16);
        let mut byte_idx = 0;
        for i in 0..5 {
            let word_bytes = self.state[i].to_le_bytes();
            for &byte in &word_bytes {
                if byte_idx < byte_len {
                    result[byte_idx] = byte;
                    byte_idx += 1;
                } else {
                    break;
                }
            }
            if byte_idx >= byte_len {
                break;
            }
        }
        // Mask the last byte if m is not a multiple of 8
        if m % 8 != 0 && byte_len > 0 {
            let mask = (1u8 << (m % 8)) - 1;
            result[byte_len - 1] &= mask;
        }        
        result
    }

    // Ascon-p12 permutation implementation
    fn ascon_p12(&mut self) {
        // Round constants for 12 rounds (starting from round 0)
        const ROUND_CONSTANTS: [u64; 12] = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b];
        // Perform 12 rounds
        for round in 0..12 {
            // Step 1: Add round constant to x2
            self.state[2] ^= ROUND_CONSTANTS[round];
            // Step 2: Substitution layer (5-bit S-box applied to each column)
            for i in 0..64 {
                let t0 = self.state[0] >> i & 1;
                let t1 = self.state[1] >> i & 1;
                let t2 = self.state[2] >> i & 1;
                let t3 = self.state[3] >> i & 1;
                let t4 = self.state[4] >> i & 1;
                // Ascon 5-bit S-box
                let s0 = t0 ^ (!t1 & t2) ^ t4;
                let s1 = t1 ^ (!t2 & t3) ^ t0;
                let s2 = t2 ^ (!t3 & t4) ^ t1 ^ 1;
                let s3 = t3 ^ (!t4 & t0) ^ t2;
                let s4 = t4 ^ (!t0 & t1) ^ t3;
                // Update state bits
                self.state[0] = (self.state[0] & !(1u64 << i)) | (s0 << i);
                self.state[1] = (self.state[1] & !(1u64 << i)) | (s1 << i);
                self.state[2] = (self.state[2] & !(1u64 << i)) | (s2 << i);
                self.state[3] = (self.state[3] & !(1u64 << i)) | (s3 << i);
                self.state[4] = (self.state[4] & !(1u64 << i)) | (s4 << i);
            }

            // Step 3: Linear diffusion layer
            // x0 ← Σ0(x0) = x0 ⊕ (x0 ⋙ 19) ⊕ (x0 ⋙ 28)
            self.state[0] ^= self.state[0].rotate_right(19) ^ self.state[0].rotate_right(28);
            // x1 ← Σ1(x1) = x1 ⊕ (x1 ⋙ 61) ⊕ (x1 ⋙ 39)
            self.state[1] ^= self.state[1].rotate_right(61) ^ self.state[1].rotate_right(39);
            // x2 ← Σ2(x2) = x2 ⊕ (x2 ⋙ 1) ⊕ (x2 ⋙ 6)
            self.state[2] ^= self.state[2].rotate_right(1) ^ self.state[2].rotate_right(6);
            // x3 ← Σ3(x3) = x3 ⊕ (x3 ⋙ 7) ⊕ (x3 ⋙ 41)
            self.state[3] ^= self.state[3].rotate_right(7) ^ self.state[3].rotate_right(41);
            // x4 ← Σ4(x4) = x4 ⊕ (x4 ⋙ 10) ⊕ (x4 ⋙ 17)
            self.state[4] ^= self.state[4].rotate_right(10) ^ self.state[4].rotate_right(17);
        }
    }

    // Process data in rate-sized blocks
    fn process_data_blocks(&mut self, data: &[u8]) {
        let rate_bytes = 16; // fixed value of the rate : Ascon-128a
        let mut processed = 0;
        // Process full blocks
        while processed + rate_bytes <= data.len() {
                    self.absorb(&data[processed..processed + rate_bytes], rate_bytes * 8);
                    self.ascon_p12();
                    processed += rate_bytes;
                }
        // Process final block with padding
        if processed < data.len() { let mut final_block = [0u8; 32]; // Max rate_bytes we expect
                                    let remaining = data.len() - processed;
                                    final_block[..remaining].copy_from_slice(&data[processed..]);
                                    final_block[remaining] = 0x80; // Add padding bit   
                                    self.absorb(&final_block[..rate_bytes], rate_bytes * 8);
                                    self.ascon_p12();
                                    } 
        else {  // Data was exactly rate-aligned, add padding block
                let mut padding_block = [0u8; 32];
                padding_block[0] = 0x80;
                self.absorb(&padding_block[..rate_bytes], rate_bytes * 8);
                self.ascon_p12();
            }
    }
    
    // Initialize the sponge with domain separation, key, and context
    fn initialize_state(&mut self, seed: [u8; 32])  {
        // Prepare the input: domain tag + key + context
        let domain_tag = b"SK";
        let context = b"PSS-POINT-SEED";
        // Calculate total input size
        let total_len = domain_tag.len() + seed.len() + context.len();
        let mut input = [0u8; 64]; // Should be enough for our inputs
        let mut offset = 0;
        input[offset..offset + domain_tag.len()].copy_from_slice(domain_tag);
        offset += domain_tag.len();
        input[offset..offset + seed.len()].copy_from_slice(&seed);
        offset += seed.len();
        input[offset..offset + context.len()].copy_from_slice(context);
        // Process input in rate-sized blocks
        self.process_data_blocks( &input[..total_len])
    }
    
    fn get_value_128bit(&mut self, i: usize) -> GF128 {
        // Absorb the index
        let index_bytes = (i as u16).to_be_bytes();
        self.absorb(&index_bytes, 16); // Only 16 bits for the index
        self.ascon_p12();
        // Squeeze 128 bits
        let output_bytes = self.squeeze(128);
        GF128::from(&output_bytes)
    }
}

pub struct VandermondeGenerator {
    seed: [u8; 32]
}

impl VandermondeGenerator {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {  seed }
    }
    // Generate N_pt distinct field elements
    fn generate_points_128bit(&self, m:usize) -> (GF128Vector,GF128Vector) {
        let mut e_vect = GF128Vector::new(2*m);
        let mut x_vect = GF128Vector::new(2*m);
        let mut counter = 0;
        let mut nb_pt =0;
        let mut base_state = AsconDeriver::new();
        base_state.initialize_state(self.seed);
        while nb_pt < 4*m {
            let point = base_state.get_value_128bit(counter);
            // Check for collisions and ensure distinctness
            if !e_vect.elements.iter().any(|p| p == &point) 
              &!x_vect.elements.iter().any(|p| p == &point) 
                        {   if counter< 2*m {e_vect.elements[counter]=point}
                            else {x_vect.elements[counter-2*m]=point};
                            nb_pt+=1;
                        }
            counter += 1;
            // Safety check to prevent infinite loops
            if counter > m * 40 {
                panic!("Too many collisions encountered during point generation");
            }
        }
        (e_vect,x_vect)
    }    
}

pub fn gen_params(m:usize) {
        let data =b"PSS-FIELD-GF128";
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();        
        let seed  : [u8; 32] = result[..32].try_into().unwrap();        
        println!("len seed ={}",result.len());
        println!("seed =");
        for i in result {print!("{:0x},",i)};
        let generator = VandermondeGenerator::new(seed);
        let (interpolation_points, evaluation_points) = generator.generate_points_128bit(m);
       
        println!("interpolation points :");
        for i in 0..interpolation_points.true_size {println!("{:0x}",interpolation_points.elements[i])}
        println!("evaluation points :");
        for i in 0..evaluation_points.true_size {println!("{:0x}",evaluation_points.elements[i])}        // Verify all points are distinct
        let mut all_points = GF128Vector::new(2*m);
        for i in 0..m {all_points.elements[i]= interpolation_points.elements[i];
                              all_points.elements[i+m]= evaluation_points.elements[i];  }        
        // Check distinctness manually since we can't use HashSet
        for i in 0..all_points.true_size {
            for j in i + 1..all_points.true_size {
                assert_ne!(all_points.elements[i], all_points.elements[j], "Found duplicate points");
            }
        }
        let v =GF128Matrix::vandermonde(&interpolation_points);
        let vt =GF128Matrix::vandermonde(&evaluation_points);
        println!("V = {:0x}",v);
        println!("Vt = {:0x}",vt);
        let v1 =v.extract_submatrix(5);
        let vt1 = vt.extract_submatrix(5);
        let iv1 =v1.invert().unwrap();
        let m1 = vt1.multiply(&iv1);
        println!("m1 = {:0x}",m1);
        let d1 = v1.multiply(&vt1.invert().unwrap());
        println!("d1 = {:0x}",d1);
        let iv =v.invert().unwrap();
        let m2 = vt.multiply(&iv);
        println!("m2 = {:0x}",m2);
        let iv =vt.invert().unwrap();
        let d2 = v.multiply(&iv);
        println!("d2 = {:0x}",d2);
        for r in 1..4{
            let v3 = v.extract_submatrix(m+r);
            let vt3 = vt.extract_submatrix(m+r);
            let iv3 =v3.invert().unwrap();
            let m3=vt3.multiply(&iv3);
            println!("m3({}) = {:0x}",r,m3);
            println!("d3({}) = {:0x}",r,m3.invert().unwrap());
        }


    }


