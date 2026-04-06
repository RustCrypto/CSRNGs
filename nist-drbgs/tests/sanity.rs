use nist_drbg_rs::{Aes128CtrDrbg, HmacSha1Drbg, Sha1Drbg, TdeaCtrDrbg};
use nist_drbg_rs::{Drbg, Policy};

use hex_lit::hex;

#[test]
fn test_hash() {
    let entropy: &[u8] = &hex!("136cf1c174e5a09f66b962d994396525");
    let nonce: &[u8] = &hex!("fff1c6645f19231f");
    let returned_bytes: &[u8] = &hex!(
        "0e28130fa5ca11edd3293ca26fdb8ae1810611f78715082ed3841e7486f16677b28e33ffe0b93d98ba57ba358c1343ab2a26b4eb7940f5bc639384641ee80a25140331076268bd1ce702ad534dda0ed8"
    );
    let mut drbg = Sha1Drbg::new(entropy, nonce, &[], Policy::default()).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_hash_add() {
    let entropy: &[u8] = &hex!("c3ef82ce241f02e4298b118ca4f16225");
    let nonce: &[u8] = &hex!("15e32abbae6b7433");
    let add1: &[u8] = &hex!("2b790052f09b364d4a8267a0a7de63b8");
    let add2: &[u8] = &hex!("2ee0819a671d07b5085cc46aa0e61b56");
    let returned_bytes: &[u8] = &hex!(
        "5825fa1d1dc33c64cdc8690682eff06039e79508c3af48e880f8227d5f9aaa14b3bc76baee477ebbb5c45547134179223257525e8f3afefb78b59da032f1006d74c9831375a677eab3239c94ebe3f7fa"
    );
    let mut drbg = Sha1Drbg::new(entropy, nonce, &[], Policy::default()).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.generate_ctx(&mut buf, add1);
    let _ = drbg.generate_ctx(&mut buf, add2);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_hmac() {
    let entropy: &[u8] = &hex!("e91b63309e93d1d08e30e8d556906875");
    let nonce: &[u8] = &hex!("f59747c468b0d0da");
    let returned_bytes: &[u8] = &hex!(
        "b7928f9503a417110788f9d0c2585f8aee6fb73b220a626b3ab9825b7a9facc79723d7e1ba9255e40e65c249b6082a7bc5e3f129d3d8f69b04ed1183419d6c4f2a13b304d2c5743f41c8b0ee73225347"
    );
    let mut drbg = HmacSha1Drbg::new(entropy, nonce, &[], Policy::default()).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_hmac_add() {
    let entropy: &[u8] = &hex!("32c1ca125223de8de569697f92a37c67");
    let nonce: &[u8] = &hex!("72d4cc4f0544d409");
    let add1: &[u8] = &hex!("9e98cc8e0f8eb84d1911c1775a5703bb");
    let add2: &[u8] = &hex!("593aa3a300e5c907a011dd5a3dcd77e2");
    let returned_bytes: &[u8] = &hex!(
        "942909a9d380aa5d4e3af69093a8fa513ee545b9bf9e1b81c5f30966db3e5cb52f8b1b6fe440d592e5fe4a972c36aa498035e2442f82910c5cd095c7f4b4c7e7555c4669cca481cdfbfda167b5d6f8d5"
    );
    let mut drbg = HmacSha1Drbg::new(entropy, nonce, &[], Policy::default()).unwrap();

    let mut buf: [u8; 80] = [0; 80];
    let _ = drbg.generate_ctx(&mut buf, add1);
    let _ = drbg.generate_ctx(&mut buf, add2);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_tdea_ctr() {
    let entropy: &[u8] = &hex!("4cd97f1701716d1a22f90b55c569c8f2b91aa53322653dcae809abc5c6");
    let nonce: &[u8] = &[];
    let returned_bytes: &[u8] =
        &hex!("4353dd937ec55e6733cf7a5d2cea557ce8e3fcc6cdb18e44395e4b1c4669c9d1");
    let mut drbg = TdeaCtrDrbg::new(entropy, nonce, Policy::default()).unwrap();

    let mut buf: [u8; 32] = [0; 32];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_tdea_ctr_add() {
    let entropy: &[u8] = &hex!("37a71a5e7adb233e438dbca9e2e89d0a1c927de79554bc8650f70d5141");
    let add1: &[u8] = &hex!("531197ce30a47ed6703b4f2f1afef74428fa86f42637906c99085903fd");
    let add2: &[u8] = &hex!("e3737cb398aa345f3747da9b7f8c7d9144f72727c4ff05885f9d0d69e4");
    let returned_bytes: &[u8] =
        &hex!("1b064c87608031d0082f7c300ef0f4fdd2590c88b0ef0f0c474341e47b062b6e");
    let mut drbg = TdeaCtrDrbg::new(entropy, &[], Policy::default()).unwrap();

    let mut buf: [u8; 32] = [0; 32];
    let _ = drbg.generate_ctx(&mut buf, add1);
    let _ = drbg.generate_ctx(&mut buf, add2);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_aes_ctr() {
    let entropy: &[u8] = &hex!("ce50f33da5d4c1d3d4004eb35244b7f2cd7f2e5076fbf6780a7ff634b249a5fc");
    let returned_bytes: &[u8] = &hex!(
        "6545c0529d372443b392ceb3ae3a99a30f963eaf313280f1d1a1e87f9db373d361e75d18018266499cccd64d9bbb8de0185f213383080faddec46bae1f784e5a"
    );
    let mut drbg = Aes128CtrDrbg::new(entropy, &[], Policy::default()).unwrap();

    let mut buf: [u8; 64] = [0; 64];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_aes_ctr_add() {
    let entropy: &[u8] = &hex!("6bd4f2ae649fc99350951ff0c5d460c1a9214154e7384975ee54b34b7cae0704");
    let add1: &[u8] = &hex!("ecd4893b979ac92db1894ae3724518a2f78cf2dbe2f6bbc6fda596df87c7a4ae");
    let add2: &[u8] = &hex!("b23e9188687c88768b26738862c4791fa52f92502e1f94bf66af017c4228a0dc");
    let returned_bytes: &[u8] = &hex!(
        "5b2bf7a5c60d8ab6591110cbd61cd387b02de19784f496d1a109123d8b3562a5de2dd6d5d1aef957a6c4f371cecd93c15799d82e34d6a0dba7e915a27d8e65f3"
    );
    let mut drbg = Aes128CtrDrbg::new(entropy, &[], Policy::default()).unwrap();

    let mut buf: [u8; 64] = [0; 64];
    let _ = drbg.generate_ctx(&mut buf, add1);
    let _ = drbg.generate_ctx(&mut buf, add2);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_aes_ctr_df() {
    let entropy: &[u8] = &hex!("890eb067acf7382eff80b0c73bc872c6");
    let nonce: &[u8] = &hex!("aad471ef3ef1d203");
    let returned_bytes: &[u8] = &hex!(
        "a5514ed7095f64f3d0d3a5760394ab42062f373a25072a6ea6bcfd8489e94af6cf18659fea22ed1ca0a9e33f718b115ee536b12809c31b72b08ddd8be1910fa3"
    );
    let mut drbg = Aes128CtrDrbg::new_with_df(entropy, nonce, &[], Policy::default()).unwrap();

    let mut buf: [u8; 64] = [0; 64];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}

#[test]
fn test_aes_ctr_df_ps() {
    let entropy: &[u8] = &hex!("e10bc28a0bfddfe93e7f5186e0ca0b3b");
    let nonce: &[u8] = &hex!("9ff477c18673840d");
    let personalization_string = &hex!("c980dedf9882ed4464a674967868f143");
    let returned_bytes: &[u8] = &hex!(
        "35b00df6269b6641fd4ccb354d56d851de7a77527e034d60c9e1a9e1525a30ed361fded89d3dccb978d4e7a9e100ebf63062735b52831c6f0a1d3e1bdc5ebc72"
    );
    let mut drbg =
        Aes128CtrDrbg::new_with_df(entropy, nonce, personalization_string, Policy::default())
            .unwrap();

    let mut buf: [u8; 64] = [0; 64];
    let _ = drbg.generate(&mut buf);
    let _ = drbg.generate(&mut buf);
    assert_eq!(buf, returned_bytes);
}
