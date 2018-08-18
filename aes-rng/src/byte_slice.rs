/// Trait for casting types to byte slices.
pub trait AsByteSliceMut {
    /// Return a mutable reference to self as a byte slice
    fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8];

    /// Call `to_le` on each element (i.e. byte-swap on Big Endian platforms).
    fn to_le(&mut self);
}

impl AsByteSliceMut for [u8] {
    #[inline]
    fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
        self
    }

    #[inline]
    fn to_le(&mut self) {}
}

macro_rules! impl_as_byte_slice {
    ($t:ty) => {
        impl AsByteSliceMut for [$t] {
            #[inline]
            fn as_byte_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
                unsafe {
                    ::std::slice::from_raw_parts_mut(&mut self[0]
                        as *mut $t
                        as *mut u8,
                        self.len() * ::std::mem::size_of::<$t>()
                    )
                }
            }

            #[inline]
            fn to_le(&mut self) {
                for x in self {
                    *x = x.to_le();
                }
            }
        }
    }
}

impl_as_byte_slice!(u32);
