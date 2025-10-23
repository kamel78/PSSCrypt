use crate::aes_ciphers::common_fns::*;

// Software based implementation of AES 256bit encryption/decryption algorithm
pub struct AES256 { round_keys: [[u8; 16]; 15], // 14 + 1 rounds
                    }

impl AES256 {   
    pub fn new(key: &[u128]) -> Self {
        assert!(key.len() == 2, "AES-256 key must contain two 128-bit values");
        let mut key_bytes = [0u8; 32];
        key_bytes[0..16].copy_from_slice(&key[0].to_be_bytes());
        key_bytes[16..32].copy_from_slice(&key[1].to_be_bytes());
        Self {  round_keys: Self::key_expansion(&key_bytes),    }
    }

    
    fn key_expansion(key: &[u8; 32]) -> [[u8; 16]; 15] {
            let mut w = [0u8; 240];
            w[..32].copy_from_slice(key);
            let mut i = 8;
            let mut r = 0;
            while i < 60 {
                let mut temp = [
                    w[4*(i-1)], w[4*(i-1)+1], w[4*(i-1)+2], w[4*(i-1)+3]
                ];
                if i % 8 == 0 {
                    temp.rotate_left(1);
                    for t in temp.iter_mut() {
                        *t = SBOX[*t as usize];
                    }
                    temp[0] ^= RCON256[r];
                    r += 1;
                } else if i % 8 == 4 {
                    for t in temp.iter_mut() {
                        *t = SBOX[*t as usize];
                    }
                }
                for j in 0..4 {
                    w[4*i + j] = w[4*(i-8) + j] ^ temp[j];
                }
                i += 1;
            }
            let mut round_keys = [[0u8; 16]; 15];
            for (r, rk) in round_keys.iter_mut().enumerate() {
                rk.copy_from_slice(&w[16*r..16*r+16]);
            }
            round_keys
        }

    
    pub fn encrypt_block(&self, block: u128) -> u128 {
                let mut state = u128_to_state(block);
                add_round_key(&mut state, &self.round_keys[0]);
                for round in 1..14 {    sub_bytes(&mut state);
                                            shift_rows(&mut state);
                                            mix_columns(&mut state);
                                            add_round_key(&mut state, &self.round_keys[round]);
                                        }
                sub_bytes(&mut state);
                shift_rows(&mut state);
                add_round_key(&mut state, &self.round_keys[14]);
                state_to_u128(&state)
            }

            

    pub fn decrypt_block(&self, block: u128) -> u128 {        
            let mut state = u128_to_state(block);
            add_round_key(&mut state, &self.round_keys[14]);
            for round in (1..14).rev() {    inv_shift_rows(&mut state);
                                                inv_sub_bytes(&mut state);
                                                add_round_key(&mut state, &self.round_keys[round]);
                                                inv_mix_columns(&mut state);
                                            }
            inv_shift_rows(&mut state);
            inv_sub_bytes(&mut state);
            add_round_key(&mut state, &self.round_keys[0]);
            state_to_u128(&state)
        }
    
    
    pub fn setkey(&mut self,key: &[u128]){
            self.round_keys = [[0u8; 16]; 15];
            let mut key_bytes = [0u8; 32];
            key_bytes[0..16].copy_from_slice(&key[0].to_be_bytes());
            key_bytes[16..32].copy_from_slice(&key[1].to_be_bytes());
            AES256::key_expansion(&key_bytes);       
        }
}

