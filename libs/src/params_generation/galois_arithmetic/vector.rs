use crate::params_generation::galois_arithmetic::field::MAX_VECTOR_ELEMENTS;

use super:: GF128;
use smallvec::SmallVec;

#[derive( Clone, Debug)]
pub struct GF128Vector{
    pub elements:SmallVec<[GF128; MAX_VECTOR_ELEMENTS]>,
    pub true_size:usize
}

impl GF128Vector {

    pub fn new(true_size:usize)-> Self{
        let elements = core::array::from_fn(|_| GF128::from(0)).into();
        GF128Vector { elements , true_size}
    }

    pub fn random(true_size: usize) -> Self {
        let elements: SmallVec::<[GF128; MAX_VECTOR_ELEMENTS]> = core::array::from_fn(|_| GF128::random()).into();
        GF128Vector { elements, true_size }
    }  
}

