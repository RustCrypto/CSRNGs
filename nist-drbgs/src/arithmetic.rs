/// Compute a + b + c where a, b < 256 and c = 0 or 1
/// The max value is 2*255 + 1 = 256 + 255 which can be represented
/// as a u8 with one additional bit to detect if there was an overflow
#[inline]
const fn carrying_add(x: u8, y: u8, carry: bool) -> (u8, bool) {
    let (a, b) = x.overflowing_add(y);
    let (c, d) = a.overflowing_add(carry as u8);
    (c, b | d)
}

/// Compute a + 1 mod 2^(8*n)
/// Details: We interpret the slice &[u8] of length n as an integer
/// modulo 2^(8*n) in big endian. This function adds one to the top
/// byte and then propagates this though the slice to the bottom byte.
/// Carry here is ignored due to the modulus.
pub(crate) fn increment(a: &mut [u8]) {
    let mut carry = true;
    for ai in a.iter_mut().rev() {
        (*ai, carry) = ai.overflowing_add(carry as u8)
    }
}

/// Compute a + b mod 2^(8*n)
/// Details: We interpret the slices &[u8] as integers modulo 2^(8*n)
/// in big endian, where n is the length of a and we assume that b has
/// length at most n.
/// Addition is computed by summing from the last to the first byte of
/// a computing ai + bi + c, where c is a carry bit which tracks any
/// overflow during additions. Carry after the sum of the bottom byte
/// is ignored due to the modulus
pub(crate) fn add_into(a: &mut [u8], b: &[u8]) {
    let mut carry = false;
    let a_len = a.len();
    let b_len = b.len();
    for i in 1..=a_len {
        let ai = &mut a[a_len - i];
        let bi = b_len.checked_sub(i).map(|idx| b[idx]).unwrap_or(0);
        (*ai, carry) = carrying_add(*ai, bi, carry);
    }
}
