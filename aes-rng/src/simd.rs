#[cfg(target_arch = "x86")]
use std::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

/// SIMD type used by the fast-key erasure RNG.
///
/// This provides an abstraction over the relevant SIMD instructions.
#[derive(Debug, Clone, Copy)]
pub struct M128(pub __m128i);

impl M128 {
    #[inline]
    pub unsafe fn load(mem_addr: *const u8) -> M128 {
        M128(_mm_loadu_si128(mem_addr as *const __m128i))
    }

    #[inline]
    pub unsafe fn store(&self, mem_addr: *mut u8) {
        _mm_storeu_si128(mem_addr as *mut __m128i, self.0);
    }

    #[allow(unused)]  // Only used in tests.
    #[inline]
    pub fn bytes(&self) -> [u8; 16] {
        unsafe {
            #[repr(align(16))]
            struct Aligned([u8; 16]);
            let mut buf: Aligned = ::std::mem::uninitialized();
            self.store(buf.0.as_mut_ptr());
            buf.0
        }
    }

    #[inline]
    pub fn encrypt(self, round_key: M128) -> M128 {
        unsafe { M128(_mm_aesenc_si128(self.0, round_key.0)) }
    }

    #[inline]
    pub fn encrypt_last(self, round_key: M128) -> M128 {
        unsafe { M128(_mm_aesenclast_si128(self.0, round_key.0)) }
    }
}

impl ::std::ops::BitXor<M128> for M128 {
    type Output = M128;

    #[inline]
    fn bitxor(self, rhs: M128) -> M128 {
        unsafe { M128(_mm_xor_si128(self.0, rhs.0)) }
    }
}

macro_rules! shiftl {
    ($a:expr, $imm8:expr) => ({
        #[cfg(target_arch = "x86")]
        use std::arch::x86::_mm_slli_si128;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_mm_slli_si128;

        let M128(a) = $a;
        unsafe { M128(_mm_slli_si128(a, $imm8)) }
    });
}

macro_rules! shuffle {
    ($a:expr, $imm8:expr) => ({
        #[cfg(target_arch = "x86")]
        use std::arch::x86::_mm_shuffle_epi32;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_mm_shuffle_epi32;

        let M128(a) = $a;
        unsafe { M128(_mm_shuffle_epi32(a, $imm8)) }
    });
}

macro_rules! keygenassist {
    ($a:expr, $imm8:expr) => ({
        #[cfg(target_arch = "x86")]
        use std::arch::x86::_mm_aeskeygenassist_si128;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::_mm_aeskeygenassist_si128;

        let M128(a) = $a;
        unsafe { M128(_mm_aeskeygenassist_si128(a, $imm8)) }
    });
}

impl ::std::ops::Add<M128> for M128 {
    type Output = M128;

    #[inline]
    fn add(self, rhs: M128) -> M128 {
        unsafe { M128(_mm_add_epi64(self.0, rhs.0)) }
    }
}

impl ::std::convert::From<(i64, i64)> for M128 {
    #[inline]
    fn from(x: (i64, i64)) -> M128 {
        unsafe { M128(_mm_set_epi64x(x.0, x.1)) }
    }
}

impl ::std::convert::From<__m128i> for M128 {
    #[inline]
    fn from(x: __m128i) -> M128 {
        M128(x)
    }
}
