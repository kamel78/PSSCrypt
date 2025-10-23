use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128, _mm_xor_si128, _mm_slli_si128};
use std::{  arch::x86_64::{_mm_cmpeq_epi8, _mm_extract_epi64, _mm_loadu_si128, _mm_movemask_epi8, _mm_set_epi64x, _mm_setzero_si128, _mm_srli_si128}, 
            fmt, ops::{Add, AddAssign, BitXor, Div, Mul, Sub}, str::FromStr};
use rand::Rng;

pub const MAX_VECTOR_ELEMENTS :usize = 25;

#[derive(Copy, Clone, Debug)]
pub struct GF128(pub __m128i);

#[inline(always)] 
fn u128_to_m128(x: u128) -> __m128i {
        let lo = x as u64;
        let hi = (x >> 64) as u64;
        unsafe { _mm_set_epi64x(hi as i64, lo as i64) }
}

#[inline(always)] 
fn m128_to_u128(x: __m128i) -> u128 {
    unsafe {    let lo = _mm_extract_epi64(x, 0) as u64;
                let hi = _mm_extract_epi64(x, 1) as u64;
                (hi as u128) << 64 | lo as u128
           }
}

// Multiply two 128-bit field elements in GF(2^128) #[target_feature(enable = "pclmulqdq")]
#[inline(always)] 
fn gf_mul(a: __m128i, b: __m128i) -> __m128i {   
    unsafe {    let h0 = _mm_clmulepi64_si128(a, b, 0x00);  // a_low * b_low
                let h1 = _mm_clmulepi64_si128(a, b, 0x01);  // a_low * b_high  
                let h2 = _mm_clmulepi64_si128(a, b, 0x10);  // a_high * b_low
                let h3 = _mm_clmulepi64_si128(a, b, 0x11);  // a_high * b_high
                let h1h2 = _mm_xor_si128(h1, h2);   
                let lo = _mm_xor_si128(h0, _mm_slli_si128(h1h2, 8));
                let hi = _mm_xor_si128(h3, _mm_srli_si128(h1h2, 8));

                // Reduce a 256-bit value modulo x^128 + x^7 + x^2 + x + 1
                // The polynomial can be represented as the bit pattern 10000111 = 0x87 when we consider x^128 ≡ x^7 + x^2 + x + 1
                let poly = _mm_set_epi64x(0, 0x87);       
                let t0 = _mm_clmulepi64_si128(hi, poly, 0x00);
                let t1 = _mm_clmulepi64_si128(hi, poly, 0x01);
                let v0 = _mm_xor_si128(lo, t0);
                let v1 = _mm_xor_si128(v0, _mm_slli_si128(t1, 8));        
                let t2 = _mm_srli_si128(t1, 8);
                let t3 = _mm_clmulepi64_si128(t2, poly, 0x00);        
                _mm_xor_si128(v1, t3)
            }
}

#[inline(always)] 
fn gf_inv(a: __m128i) -> __m128i {
    unsafe {
        let zero = _mm_setzero_si128();
        if _mm_extract_epi64(a, 0) == 0 && _mm_extract_epi64(a, 1) == 0 {return zero;}
        // Precompute odd powers for 4-bit windows: a^1, a^3, a^5, a^7, a^9, a^11, a^13, a^15
        let mut table = [_mm_setzero_si128(); 16];
        table[1] = a;  
        let a_squared = gf_mul(a, a);  // a^2        
        for i in (3..16).step_by(2) {table[i] = gf_mul(table[i - 2], a_squared);}
        let mut even_table = [_mm_setzero_si128(); 16];
        even_table[2] = a_squared;
        for i in (4..16).step_by(2) {even_table[i] = gf_mul(even_table[i - 2], a_squared);}
        let exponent: u128 = 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE;
        let mut result = u128_to_m128(1);
        let mut bit_pos = 128;
        while bit_pos >= 4 {    bit_pos -= 4;
                                let window_value = ((exponent >> bit_pos) & 0xF) as usize;
                                result = gf_mul(result, result);
                                result = gf_mul(result, result);
                                result = gf_mul(result, result);
                                result = gf_mul(result, result);
                                if window_value != 0 {
                                    if (window_value & 1) == 1 {
                                        result = gf_mul(result, table[window_value]);
                                    } else {
                                        result = gf_mul(result, even_table[window_value]);
                                    }
                                }
                            }
        result
    }   
}


impl GF128 {
    #[inline(always)] 
    pub fn is_zero(&self)->bool
        {
            self.to_u128() == 0
        }
    
    #[inline(always)] 
    pub fn is_one(&self)->bool
        {
            self.to_u128() == 1
        }
    
    #[inline(always)] 
        pub fn to_u128(&self)-> u128           // Convert to u128
        {
            m128_to_u128(self.0)   
        }
    
    #[inline(always)] 
    pub fn random() -> Self
        {                                           // Generate a random element
            GF128(u128_to_m128(rand::rng().random::<u128>()))
        }
    
    #[inline(always)] 
    pub fn addto(&self, rhs: &GF128) -> Self 
        {                            // Add two Gf128 element 
            unsafe {GF128(_mm_xor_si128(self.0 , rhs.0))}
        }
    
    #[inline(always)] 
    pub fn subtract(&self, rhs: &GF128) -> Self 
        {                            // Substract two Gf128 element (same as Add)
            unsafe {GF128(_mm_xor_si128(self.0 , rhs.0))}
        }

    #[inline(always)] 
    pub fn multiply(&self, rhs: &GF128) -> Self 
        {                       // Multiply two Gf128 element 
            GF128(gf_mul(self.0, rhs.0))
        }
    
    #[inline(always)] 
    pub fn invert(&self) -> Self 
        {                                       // Inverte a Gf128 element 
            GF128(gf_inv(self.0))
        }

    #[inline(always)] 
    pub fn divide(&self, rhs: &GF128) -> Self 
        {                          // Divide two Gf128 element 
            let invc = rhs.invert();
            self.multiply(&invc) 
        }

    #[inline(always)] 
    pub fn pow(&self, exponent: usize) -> Self 
        {
            if exponent == 0 { return GF128::from(1u128); }
            if exponent == 1 { return *self;     }
            if self.is_zero() {  return GF128::from(0u128);  }
            let mut result = GF128::from(1u128); 
            let mut base = self.clone();       
            let mut exp = exponent;    
            while exp > 0 {
                if exp & 1 == 1 {result = result.multiply(&base);}
                base = base.multiply(&base);
                exp >>= 1;
            }        
            result
        }

    pub fn to_bytes(&self) ->[u8;16]
        {
            m128_to_u128(self.0).to_be_bytes()
        }
       
}

impl From<u128> for GF128 
    {
        fn from(input: u128) -> Self {
            GF128(u128_to_m128(input))
        }
    }

impl From<&[u8; 16]> for GF128 
    {
        fn from(bytes: &[u8; 16]) -> Self {
            GF128(u128_to_m128(u128::from_be_bytes(*bytes)))
        }
    }

impl From<&[u64; 2]> for GF128 
    {
        fn from(qwords: &[u64; 2]) -> Self {
            let mut buf = [0u8; 16];
            buf[0..8].copy_from_slice(&qwords[0].to_be_bytes());
            buf[8..16].copy_from_slice(&qwords[1].to_be_bytes());
            GF128(u128_to_m128(u128::from_be_bytes(buf)))
        }
    }

impl From<&[u16; 8]> for GF128 
    {
        fn from(words: &[u16; 8]) -> Self {
            let mut buf = [0u8; 16];
            for (i, word) in words.iter().enumerate() {
                let bytes = word.to_be_bytes();
                buf[2 * i] = bytes[0];
                buf[2 * i + 1] = bytes[1];
            }
            GF128(u128_to_m128(u128::from_be_bytes(buf)))
        }
    }

impl From<&[u32; 4]> for GF128 
    {
        fn from(dwords: &[u32; 4]) -> Self {
            let mut buf = [0u8; 16];
            for (i, dword) in dwords.iter().enumerate() {
                let bytes = dword.to_be_bytes();
                buf[4 * i..4 * (i + 1)].copy_from_slice(&bytes);
            }
            GF128(u128_to_m128(u128::from_be_bytes(buf)))
        }
    }

impl From< &[u8]> for GF128 
    {
        fn from(bytes:  &[u8]) -> Self {
            let mut buf = [0u8; 16];
            let len = std::cmp::min(bytes.len(), 16);
            buf[..len].copy_from_slice(&bytes[..len]);
            GF128(u128_to_m128(u128::from_be_bytes(buf)))
        }
    }


impl FromStr for GF128 
    {
        type Err = &'static str;       
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let s = s.trim();
            let value = if s.starts_with("0x") || s.starts_with("0X") {
                let hex_str = s.trim_start_matches("0x").trim_start_matches("0X");
                if hex_str.len() > 32 {
                    return Err("Hex string too long for Gf128");
                }
                let padded = format!("{:0>32}", hex_str);
                u128::from_str_radix(&padded, 16)
                    .map_err(|_| "Invalid hexadecimal string")?
            } else {
                u128::from_str(s)
                    .map_err(|_| "Invalid decimal string")?
            };        
            unsafe {
                let m128i = _mm_loadu_si128(&value as *const u128 as *const __m128i);
                Ok(GF128(m128i))
            }
        }
    }

impl fmt::LowerHex for GF128 
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "0x{:x}", self.to_u128())
        }
    }

impl fmt::Display for GF128 
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(width) = f.width() {
                if width == 32 {
                    write!(f, "0x{:032x}", self.to_u128())
                } else {
                    write!(f, "{}", self.to_u128())
                }
            } else {
                write!(f, "{}", self.to_u128())
            }
        }
    }


impl Add for GF128 
    {
        type Output = GF128;
        #[inline(always)] 
        fn add(self, rhs: GF128) -> GF128 {
            self.addto(&rhs)
        }
    }

impl AddAssign for GF128 
    {
        #[inline(always)] 
        fn add_assign(&mut self, other: Self) {
            // In GF(2^128), addition is XOR
        unsafe {
                self.0 = _mm_xor_si128(self.0, other.0);
            }
        }
    }

impl AddAssign<&GF128> for GF128 
    {
        #[inline(always)] 
        fn add_assign(&mut self, other: &Self) {
            unsafe {
                self.0 = _mm_xor_si128(self.0, other.0);
            }
        }
    }


impl Sub for GF128 
    {
        type Output = GF128;
        #[inline(always)] 
        fn sub(self, rhs: GF128) -> GF128 {
            self.subtract(&rhs)
        }
    }

impl BitXor for GF128 
    {
        type Output = GF128;
        #[inline(always)] 
        fn bitxor(self, rhs: GF128) -> GF128 {
            self.addto(&rhs)
        }
    }

impl Mul for GF128 
    {
        type Output = GF128;
        #[inline(always)] 
        fn mul(self, rhs: GF128) -> GF128 {
            self.multiply(&rhs)
        }
    }

impl Div for GF128 
    {
        type Output = GF128;
        #[inline(always)] 
        fn div(self, rhs: GF128) -> GF128 {
            self.divide(&rhs)
        }
    }

impl PartialEq for GF128 
    {
        #[inline(always)] 
        fn eq(&self, other: &Self) -> bool {        
        unsafe {
                let cmp = _mm_cmpeq_epi8(self.0, other.0);
                _mm_movemask_epi8(cmp) == 0xFFFF
            }    
        }
    }

