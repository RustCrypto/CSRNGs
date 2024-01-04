use hex_literal::hex;
use hmac::digest::generic_array::GenericArray;
use rand_core::{RngCore, SeedableRng};

use belt_hmac_rng::BrngHmacHbelt;

#[test]
fn test_rng() {
    let k = hex!("E9DEE72C 8F0C0FA6 2DDB49F4 6F739647 06075316 ED247A37 39CBA383 03A98BF6");
    let s = hex!("BE329713 43FC9A48 A02A885F 194B09A1 7ECDA4D0 1544AF8C A58450BF 66D2E88A");
    let y = hex!("
        AF907A0E 470A3A1B 268ECCCC C0B90F23 9FE94A2D C6E01417 9FC789CB 3C3887E4
        695C6B96 B84948F8 D76924E2 2260859D B9B5FE75 7BEDA2E1 7103EE44 655A9FEF
        648077CC C5002E05 61C6EF51 2C513B8C 24B4F3A1 57221CFB C1597E96 9778C1E4
    ");

    let seed = [k, s].concat();
    let seed = GenericArray::from_slice(&seed);

    let mut rng = BrngHmacHbelt::from_seed(*seed);
    let mut out = [0u8; 32 * 3];
    rng.fill_bytes(&mut out);
    assert_eq!(out, y);
}