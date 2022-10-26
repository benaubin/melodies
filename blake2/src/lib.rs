use std::{mem::{MaybeUninit}, ops::{Deref, DerefMut}};

use blake2::{Blake2s256, Digest, Blake2b512};
use generic_array::GenericArray;
use melodies_core::crypto::HashFunction;
use zeroize::{ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct BLAKE2s( ForcedZeroizing<Blake2s256> );
#[derive(ZeroizeOnDrop)]
pub struct BLAKE2b( ForcedZeroizing<Blake2b512> );

impl HashFunction<32> for BLAKE2s {
    fn new() -> Self where Self: Sized {
        Self(ForcedZeroizing::new(Blake2s256::new()))
    }

    const NAME: &'static str = "BLAKE2s";

    const BLOCKLEN: usize = 64;

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut *self.0, data);
    }

    fn finalize_reset(&mut self, out: &mut [u8; 32]) {
        let out = GenericArray::from_mut_slice(out);
        Digest::finalize_into_reset(&mut *self.0, out);
    }
}

impl HashFunction<64> for BLAKE2b {
    fn new() -> Self where Self: Sized {
        Self(ForcedZeroizing::new(Blake2b512::new()))
    }

    const NAME: &'static str = "BLAKE2b";

    const BLOCKLEN: usize = 129;

    fn update(&mut self, data: &[u8]) {
        Digest::update(&mut *self.0, data);
    }

    fn finalize_reset(&mut self, out: &mut [u8; 64]) {
        let out = GenericArray::from_mut_slice(out);
        Digest::finalize_into_reset(&mut *self.0, out);
    }
}

struct ForcedZeroizing<T>(MaybeUninit<T>);

impl<T> ForcedZeroizing<T> {
    const fn new(val: T) -> Self {
        Self(MaybeUninit::new(val))
    }
}

impl<T> Deref for ForcedZeroizing<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { self.0.assume_init_ref() }
    }
}

impl<T> DerefMut for ForcedZeroizing<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.0.assume_init_mut() }
    }
}

impl<T> Drop for ForcedZeroizing<T> {
    fn drop(&mut self) {
        unsafe {
            self.0.assume_init_drop();
            core::ptr::write_volatile(&mut self.0, MaybeUninit::zeroed());
        }
    }
}

impl<T> ZeroizeOnDrop for ForcedZeroizing<T> {}
 