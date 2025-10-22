use crate::aes_ciphers::common_fns::*;


// Software based implementation of AES 128bit encryption/decryption algorithm
pub struct AES128 {     round_keys: [[u8; 16]; 11], // 11 round keys (original + 10 rounds)
                   }

impl AES128 {          
    pub const NAME: &'static str = "AES";

    pub fn new(key: &[u128]) -> Self {
        let mut aes = AES128 {round_keys: [[0u8; 16]; 11]};
        aes.key_expansion(key[0]);
        aes
    }

    fn key_expansion(&mut self, key: u128) {        
        let key_bytes = key.to_be_bytes();        
        self.round_keys[0].copy_from_slice(&key_bytes);
        for round in 1..11 {     let prev_key = &self.round_keys[round - 1];
                                        let mut new_key = [0u8; 16];
                                        let mut temp = [prev_key[13], prev_key[14], prev_key[15], prev_key[12]];
                                        for byte in &mut temp { *byte = SBOX[*byte as usize];}
            new_key[0] = temp[0] ^ RCON128[round] ^ prev_key[0];
            new_key[1] = temp[1] ^ prev_key[1];
            new_key[2] = temp[2] ^ prev_key[2];
            new_key[3] = temp[3] ^ prev_key[3];
            for i in 1..4 {     let base = i * 4;
                                        let prev_base = (i - 1) * 4;
                                        for j in 0..4 { new_key[base + j] = new_key[prev_base + j] ^ prev_key[base + j];    }
                                    }
            self.round_keys[round] = new_key;
        }
    }    
    pub fn encrypt_block(&self, input: u128) -> u128 {
        let mut state = u128_to_state(input);
        add_round_key(&mut state, &self.round_keys[0]);
        for round in 1..10 {    sub_bytes(&mut state);
                                       shift_rows(&mut state);
                                       mix_columns(&mut state);
                                       add_round_key(&mut state, &self.round_keys[round]);
                                  }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.round_keys[10]);
        state_to_u128(&state)
    }

    
    pub fn decrypt_block(&self, input: u128) -> u128 {
        let mut state = u128_to_state(input);
        add_round_key(&mut state, &self.round_keys[10]);
        for round in (1..10).rev() {    inv_shift_rows(&mut state);
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
        self.round_keys = [[0u8; 16]; 11];
        self.key_expansion(key[0]);       
    }     
}


