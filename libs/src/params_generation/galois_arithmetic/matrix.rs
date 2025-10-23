use std::fmt;
use smallvec::SmallVec;
use crate::params_generation::galois_arithmetic::field::MAX_VECTOR_ELEMENTS;

use super::{field::GF128, vector::GF128Vector};

// Using SmallVec with inline capacity of MAX_VECTOR_ELEMENTS elements
type MatrixRow = SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>;
type MatrixData = SmallVec<[MatrixRow; MAX_VECTOR_ELEMENTS]>;

#[derive(Clone, Debug)]
pub struct GF128Matrix {
    pub data: MatrixData,
    true_size: usize,
}


impl GF128Matrix {
    pub fn new(size: usize) -> Self {
        let mut data = SmallVec::new();
        for _ in 0..size {  let mut row = SmallVec::new();
                            for _ in 0..size {  row.push(GF128::from(0u128))}
                            data.push(row);
                        }
        GF128Matrix { data, true_size: size }
    }

    pub fn transpose(&self) -> Self {
        let size = self.data.len();
        let mut transposed_data = SmallVec::new();        
        for j in 0..size {  let mut row = SmallVec::new();
                                   for i in 0..self.true_size {row.push(self.data[i][j]);}
            // Pad with zeros if needed
            while row.len() < size {row.push(GF128::from(0u128));}
            transposed_data.push(row);
        }
        
        GF128Matrix {data: transposed_data, true_size: size}
    }

    pub fn identity(size: usize) -> Self {
        let mut data = SmallVec::new();
        for i in 0..size {  let mut row = SmallVec::new();
            for j in 0..size {  row.push(if i == j { GF128::from(1u128) } else { GF128::from(0u128) });}
            data.push(row);
        }
        GF128Matrix { data, true_size: size }
    }

    pub fn extract_submatrix(&self, k: usize) -> Self {
        // Extract the upper-left sub matrix of order k x k
        let mut sub_data = SmallVec::new();
        for i in 0..k { let mut row = SmallVec::new();
                                for j in 0..k {row.push(self.data[i][j])}
                                sub_data.push(row);
                            }
        Self {  data: sub_data, true_size: k}
    }

    // Matrix Inversion using Gauss-jordan elimination algorithm
    #[inline(always)]
    pub fn invert(&self) -> Option<GF128Matrix> {
        let n = self.true_size;
        let mut a = self.data.clone();
        let mut inv = GF128Matrix::identity(n).data;
        for i in 0..n {
            if a[i][i].is_zero() {
                let mut found = false;
                for j in (i + 1)..n {
                    if !a[j][i].is_zero() {
                        a.swap(i, j);
                        inv.swap(i, j);
                        found = true;
                        break;
                    }
                }
                if !found {
                    return None;
                }
            }
            let inv_pivot = a[i][i].invert();
            for k in 0..n {  a[i][k] = a[i][k] * inv_pivot;
                                    inv[i][k] = inv[i][k] * inv_pivot;
                                }
            for j in 0..n { if j != i {  let factor = a[j][i];
                                                for k in 0..n {
                                                    a[j][k] = a[j][k] - factor * a[i][k];
                                                    inv[j][k] = inv[j][k] - factor * inv[i][k];
                                                }
                                            }
                                 }
            }
        Some(GF128Matrix {  data: inv,  true_size: n})
    }

    // Dedicated inversion of Vandermonde Matrix using Sherman-Morrison-Woodbury approach
    #[inline(always)]
    pub fn invert_vandermonde(&self, sub_size: usize) -> Self {
        let n = sub_size;
        let mut inv_data: SmallVec<[SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>; MAX_VECTOR_ELEMENTS]> = SmallVec::new();        
        // Initialize with zeros
        for _ in 0..self.data.len() {   let mut row = SmallVec::new();
                                        for _ in 0..self.data.len() {   row.push(GF128::from(0))}
                                        inv_data.push(row);
                                    }        
        inv_data[0][0] = GF128::from(1); // Base case: 1x1 matrix [1] has inverse [1]        
        for k in 1..n { // Current matrix is (k+1)x(k+1), previous was kxk
                                // We're adding row k and column k
                                let mut ainv_u:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]> = SmallVec::new();
                                let mut vt_ainv:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]> = SmallVec::new();
                                
                                for _ in 0..self.data.len() {   ainv_u.push(GF128::from(0));
                                                                vt_ainv.push(GF128::from(0));
                                                            }            
            // Compute A^{-1} * u (where u is new column)
            for i in 0..k { for j in 0..k {ainv_u[i] += inv_data[i][j] * self.data[j][k]}}            
            // Compute v^T * A^{-1} (where v^T is new row)
            for j in 0..k {
                                for i in 0..k { vt_ainv[j] += self.data[k][i] * inv_data[i][j];}
                        }            
            // Compute the Schur complement: d - v^T * A^{-1} * u
            let mut vt_ainv_u = GF128::from(0);
            for i in 0..k { vt_ainv_u += vt_ainv[i] * self.data[i][k]}            
            let schur_complement = self.data[k][k] + vt_ainv_u; // GF: subtraction = addition
            if schur_complement.is_zero() { panic!("Matrix is not invertible"); }            
            let gamma = schur_complement.invert();            
            // Update the inverse matrix using block inversion formula
            // Top-left block: A^{-1} + γ * (A^{-1} * u) * (v^T * A^{-1})
            for i in 0..k {
                for j in 0..k {
                    inv_data[i][j] += gamma * ainv_u[i] * vt_ainv[j];
                }
            }            
            // Top-right and bottom-left blocks
            for i in 0..k {  inv_data[i][k] = gamma * ainv_u[i]; // Top-right
                                    inv_data[k][i] = gamma * vt_ainv[i]; // Bottom-left
                                 }            
            // Bottom-right block: γ
            inv_data[k][k] = gamma;
        }        
        Self {  data: inv_data, true_size: sub_size}
    }

    // Proposed inversion of both Vandermonde Matrices of (kxk) and((k-1)x(k-1)) in a single
    // loop using Sherman-Morrison-Woodbury approach
    #[inline(always)]
    pub fn invert_vandermonde_both(&self, sub_size: usize) -> (Self, Self) {
        let n = sub_size;
        let mut inv_data: SmallVec<[SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>; MAX_VECTOR_ELEMENTS]> = SmallVec::new();
        let mut sub_inv_data: SmallVec<[SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>; MAX_VECTOR_ELEMENTS]> = SmallVec::new();        
        // Initialize with zeros
        for _ in 0..self.data.len() {   let mut row = SmallVec::new();
                                        let mut sub_row = SmallVec::new();
                                        for _ in 0..self.data.len() {   row.push(GF128::from(0));
                                                                        sub_row.push(GF128::from(0));
                                                                    }
                                        inv_data.push(row);
                                        sub_inv_data.push(sub_row);
                                    }        
        inv_data[0][0] = GF128::from(1); // Base case: 1x1 matrix [1] has inverse [1]        
        for k in 1..n {
            // Current matrix is (k+1)x(k+1), previous was kxk
            // We're adding row k and column k
            // Save the (n-1)×(n-1) submatrix inverse before the last iteration
            if k == n - 1 { for i in 0..k {
                                for j in 0..k {
                                    sub_inv_data[i][j] = inv_data[i][j];
                                }
                            }
                        }            
            let mut ainv_u:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]> = SmallVec::new();
            let mut vt_ainv:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]> = SmallVec::new();            
            for _ in 0..self.data.len() {   ainv_u.push(GF128::from(0));    vt_ainv.push(GF128::from(0))}            
            // Compute A^{-1} * u (where u is new column)
            for i in 0..k {
                for j in 0..k {
                    ainv_u[i] += inv_data[i][j] * self.data[j][k];
                }
            }            
            // Compute v^T * A^{-1} (where v^T is new row)
            for j in 0..k {
                for i in 0..k {
                    vt_ainv[j] += self.data[k][i] * inv_data[i][j];
                }
            }
            
            // Compute the Schur complement: d - v^T * A^{-1} * u
            let mut vt_ainv_u = GF128::from(0);
            for i in 0..k {
                vt_ainv_u += vt_ainv[i] * self.data[i][k];
            }            
            let schur_complement = self.data[k][k] + vt_ainv_u; // GF: subtraction = addition
            if schur_complement.is_zero() {panic!("Matrix is not invertible");}            
            let gamma = schur_complement.invert();            
            // Update the inverse matrix using block inversion formula
            // Top-left block: A^{-1} + γ * (A^{-1} * u) * (v^T * A^{-1})
            for i in 0..k {
                for j in 0..k {
                    inv_data[i][j] += gamma * ainv_u[i] * vt_ainv[j];
                }
            }            
            // Top-right and bottom-left blocks
            for i in 0..k {  inv_data[i][k] = gamma * ainv_u[i]; // Top-right
                                    inv_data[k][i] = gamma * vt_ainv[i]; // Bottom-left
                                 }            
            // Bottom-right block: γ
            inv_data[k][k] = gamma;
        }        
        let full_inverse = Self {   data: inv_data,true_size: sub_size};        
        let sub_inverse = Self {data: sub_inv_data,true_size: sub_size - 1};        
        (full_inverse, sub_inverse)
    }

    pub fn matrices_equal(&self, b: &GF128Matrix) -> bool {
        self.data == b.data
    }

    #[inline(always)]
    pub fn multiply(&self, b: &GF128Matrix) -> Self {
        let mut result_data = SmallVec::new();        
        for i in 0..self.true_size {
            let mut row = SmallVec::new();
            for j in 0..b.true_size {
                let mut sum = GF128::from(0u128);
                for k in 0..self.true_size {
                    sum = sum + (self.data[i][k] * b.data[k][j]);
                }
                row.push(sum);
            }
            result_data.push(row);
        }        
        Self {  data: result_data,  true_size: self.true_size}
    }

    #[inline(always)]
    pub fn multiply_by_vector(&self, b: &mut GF128Vector) { //in-site multiplication
        let mut result_elements = SmallVec::<[GF128; MAX_VECTOR_ELEMENTS]>::new();        
        for i in 0..b.true_size {    let mut sum = GF128::from(0);
                                            for j in 0..b.true_size {
                                                sum = sum + (self.data[i][j] * b.elements[j]);
                                            }
                                            result_elements.push(sum);
                                        }        
        // Copy back to the fixed-size array in GF128Vector
        for (i, &elem) in result_elements.iter().enumerate() {
            if i < b.elements.len() {
                b.elements[i] = elem;
            }
        }
    }

    pub fn add_mat(&self, b: &Self) -> Self {
        let mut result_data = SmallVec::new();        
        for i in 0..self.true_size {
            let mut row = SmallVec::new();
            for j in 0..self.true_size {
                row.push(self.data[i][j] + b.data[i][j]);
            }
            result_data.push(row);
        }        
        Self {  data: result_data,  true_size: self.true_size   }
    }

    pub fn sub_mat(&self, b: &Self) -> Self {
        self.add_mat(b)
    }

    pub fn random(size: usize) -> Self {
        let mut data = SmallVec::new();        
        for _ in 0..size {
            let mut row = SmallVec::new();
            for _ in 0..size {
                row.push(GF128::random());
            }
            data.push(row);
        }        
        Self {  data,   true_size: size}
    }

    #[inline(always)]
    pub fn vandermonde(x: &GF128Vector) -> Self {
        let size = x.true_size;
        let mut data = SmallVec::new();        
        for i in 0..size {
            let mut row = SmallVec::new();
            let mut power = GF128::from(1);
            for _ in 0..size {
                row.push(power);
                power = power * x.elements[i];
            }
            data.push(row);
        }        
        Self {  data,   true_size: size}
    }

}

impl fmt::Display for GF128Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for i in 0..self.true_size {
            if i > 0 {
                write!(f, " ")?;
            }
            for j in 0..self.true_size {
                write!(f, " {}", self.data[i][j])?;
            }
            if i != self.true_size - 1 {
                write!(f, ",")?;
                writeln!(f)?;
            }
        }
        write!(f, " ]")?;
        Ok(())
    }
}

impl fmt::LowerHex for GF128Matrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[")?;
        for i in 0..self.true_size {
            if i > 0 {
                write!(f, " ")?;
            }
            for j in 0..self.true_size {
                if j > 0 {
                    write!(f, " ")?;
                }
                write!(f, "{:x}", self.data[i][j])?;
            }
            if i != self.true_size - 1 {
                write!(f, ",")?;
                writeln!(f)?;
            }
        }
        write!(f, " ]")?;
        Ok(())
    }
}

impl From<Vec<Vec<u128>>> for GF128Matrix {
    fn from(arr: Vec<Vec<u128>>) -> Self {
        let true_size = arr.len();
        let mut data = SmallVec::new();
        
        for i in 0..true_size {
            let mut row = SmallVec::new();
            for j in 0..arr[i].len() {
                row.push(GF128::from(arr[i][j]));
            }
            // Pad with zeros if needed
            while row.len() < true_size {
                row.push(GF128::from(0u128));
            }
            data.push(row);
        }
        
        Self { data, true_size }
    }
}

impl From<&[&[&str]]> for GF128Matrix {
    fn from(hex_strings: &[&[&str]]) -> Self {
        let true_size = hex_strings.len();
        for row in hex_strings.iter() {
            if row.len() != true_size {
                panic!("All rows must have the same number of columns.");
            }
        }
        
        let mut data = SmallVec::new();
        
        for i in 0..hex_strings.len() {
            let mut row = SmallVec::new();
            for j in 0..hex_strings[i].len() {
                let hex = hex_strings[i][j];
                let parsed_u128 = u128::from_str_radix(hex, 16)
                    .expect(&format!("Failed to parse hexadecimal string: {}", hex));
                row.push(GF128::from(parsed_u128));
            }
            data.push(row);
        }
        
        GF128Matrix { data, true_size }
    }
}

fn parse_str_to_gf128(s: &str) -> Result<GF128, &'static str> {
    if let Ok(val) = u128::from_str_radix(s.trim_start_matches("0x"), 16) {
        return Ok(GF128::from(val));
    }
    if let Ok(val) = s.parse::<u128>() {
        return Ok(GF128::from(val));
    }
    Err("Invalid string format")
}

impl From<&Vec<Vec<&str>>> for GF128Matrix {
    fn from(hex_or_decimal_strings: &Vec<Vec<&str>>) -> Self {
        let true_size = hex_or_decimal_strings.len();
        
        // Ensure all rows are the same length
        if !hex_or_decimal_strings.iter().all(|row| row.len() == true_size) {
            panic!("Inconsistent row lengths in input.");
        }
        
        let mut data = SmallVec::new();
        
        for i in 0..hex_or_decimal_strings.len() {
            let mut row = SmallVec::new();
            for j in 0..hex_or_decimal_strings[i].len() {
                match parse_str_to_gf128(hex_or_decimal_strings[i][j]) {
                    Ok(gf_value) => {
                        row.push(gf_value);
                    }
                    Err(_) => {
                        panic!(
                            "Invalid string format in input: {}",
                            hex_or_decimal_strings[i][j]
                        );
                    }
                }
            }
            data.push(row);
        }
        
        GF128Matrix { data, true_size }
    }
}