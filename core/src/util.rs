use core::{mem::MaybeUninit, ops::{Deref, DerefMut}};

use zeroize::ZeroizeOnDrop;


pub struct ForcedZeroizing<T>(MaybeUninit<T>);

impl<T> ForcedZeroizing<T> {
    #[inline(always)] pub const fn new(val: T) -> Self {
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
 