use nist_drbg_rs::{
    Aes128CtrDrbg, Aes192CtrDrbg, Aes256CtrDrbg, Drbg, HmacSha1Drbg, HmacSha224Drbg,
    HmacSha256Drbg, HmacSha384Drbg, HmacSha512_224Drbg, HmacSha512_256Drbg, HmacSha512Drbg, Policy,
    PredictionResistance, Sha1Drbg, Sha224Drbg, Sha256Drbg, Sha384Drbg, Sha512_224Drbg,
    Sha512_256Drbg, Sha512Drbg, TdeaCtrDrbg,
};

// define a known answer test (KAT) from a test class and a test file
macro_rules! impl_kat {
    (class = $test_class:tt, $test_file:tt) => {{
        impl_kat!(@define_questions $test_class, $test_file);

        let mut buf = [0u8; 2048 / 8];
        for question in QUESTIONS {
            let policy = impl_kat!(@policy $test_class);
            let mut drbg = impl_kat!(@instantiate_drbg $test_file, question, policy);

            // For pr_false we reseed before requesting any bytes at all
            impl_kat!(@reseed_cond $test_class, drbg, question);

            let generated_bits = &mut buf[..question.returned_bits.len()];
            impl_kat!(@generate $test_class, drbg, question, generated_bits);

            assert_eq!(generated_bits, question.returned_bits);
        }
    }};

    (@policy "drbgvectors_pr_true") => { Policy::default().with_prediction_resistance(PredictionResistance::Enabled) };
    (@policy $_:tt) => { Policy::default().with_prediction_resistance(PredictionResistance::Disabled) };

    (@reseed_cond "drbgvectors_pr_false", $drbg:ident, $question:ident) => {
        $drbg.reseed_ctx(
            &$question.entropy_input_reseed,
            &$question.additional_input_reseed,
        ).unwrap();
    };
    (@reseed_cond $_:tt, $_drbg:ident, $_question:ident) => {};

    // When we use predicition resistence, the additional bytes are used for reseeding and not the generation
    (@generate "drbgvectors_pr_true", $drbg:ident, $question:ident, $generated_bits:ident) => {
        // Request the first chunk of bytes
        $drbg.reseed_ctx(&$question.entropy_input_pr_1, &$question.additional_input_1)
            .unwrap();
        $drbg.generate($generated_bits).unwrap();

        // Request the second chunk of bytes
        $drbg.reseed_ctx(&$question.entropy_input_pr_2, &$question.additional_input_2)
            .unwrap();
        $drbg.generate($generated_bits).unwrap();
    };

    // For all other cases, additional bytes are used in the reseeding itself
    (@generate $_:tt, $drbg:ident, $question:ident, $generated_bits:ident) => {
        // Request the first chunk of bytes
        $drbg.generate_ctx($generated_bits, &$question.additional_input_1)
            .unwrap();

        // Request the second chunk of bytes
        $drbg.generate_ctx($generated_bits, &$question.additional_input_2)
            .unwrap();
    };

    // match on the DRBG name and pick the appropriate type to instantiate
    (@drbg_type "3KeyTDEA_no_df")   => { TdeaCtrDrbg };
    (@drbg_type "3KeyTDEA_use_df")  => { TdeaCtrDrbg };
    (@drbg_type "AES-128_no_df")    => { Aes128CtrDrbg };
    (@drbg_type "AES-128_use_df")   => { Aes128CtrDrbg };
    (@drbg_type "AES-192_no_df")    => { Aes192CtrDrbg };
    (@drbg_type "AES-192_use_df")   => { Aes192CtrDrbg };
    (@drbg_type "AES-256_no_df")    => { Aes256CtrDrbg };
    (@drbg_type "AES-256_use_df")   => { Aes256CtrDrbg };
    (@drbg_type "Hash_SHA-1")       => { Sha1Drbg };
    (@drbg_type "Hash_SHA-224")     => { Sha224Drbg };
    (@drbg_type "Hash_SHA-256")     => { Sha256Drbg };
    (@drbg_type "Hash_SHA-384")     => { Sha384Drbg };
    (@drbg_type "Hash_SHA-512")     => { Sha512Drbg };
    (@drbg_type "Hash_SHA-512_224") => { Sha512_224Drbg };
    (@drbg_type "Hash_SHA-512_256") => { Sha512_256Drbg };
    (@drbg_type "HMAC_SHA-1")       => { HmacSha1Drbg };
    (@drbg_type "HMAC_SHA-224")     => { HmacSha224Drbg };
    (@drbg_type "HMAC_SHA-256")     => { HmacSha256Drbg };
    (@drbg_type "HMAC_SHA-384")     => { HmacSha384Drbg };
    (@drbg_type "HMAC_SHA-512")     => { HmacSha512Drbg };
    (@drbg_type "HMAC_SHA-512_224") => { HmacSha512_224Drbg };
    (@drbg_type "HMAC_SHA-512_256") => { HmacSha512_256Drbg };

    // pattern match on the CTR DRBGs as they require a special constructors
    (@instantiate_drbg "3KeyTDEA_no_df", $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg "3KeyTDEA_no_df", $question, $policy)
    };
    (@instantiate_drbg "AES-128_no_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg "AES-128_no_df",  $question, $policy)
    };
    (@instantiate_drbg "AES-192_no_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg "AES-192_no_df",  $question, $policy)
    };
    (@instantiate_drbg "AES-256_no_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg "AES-256_no_df",  $question, $policy)
    };
    (@instantiate_drbg "3KeyTDEA_use_df", $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg_with_df "3KeyTDEA_use_df", $question, $policy)
    };
    (@instantiate_drbg "AES-128_use_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg_with_df "AES-128_use_df",  $question, $policy)
    };
    (@instantiate_drbg "AES-192_use_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg_with_df "AES-192_use_df",  $question, $policy)
    };
    (@instantiate_drbg "AES-256_use_df",  $question:ident, $policy:ident) => {
        impl_kat!(@instantiate_ctr_drbg_with_df "AES-256_use_df",  $question, $policy)
    };

    // instantiate the hmac/hash DRBGs normally
    (@instantiate_drbg $drbg:tt, $question:ident, $policy:ident) => {
        <impl_kat!(@drbg_type $drbg)>::new(
            &$question.entropy_input,
            &$question.nonce,
            &$question.personalization_string,
            $policy,
        )
        .unwrap()
    };

    // instantiate the ctr DRBGs normally
    (@instantiate_ctr_drbg $drbg:tt, $question:ident, $policy:ident) => {
        <impl_kat!(@drbg_type $drbg)>::new(
            &$question.entropy_input,
            &$question.personalization_string,
            $policy,
        )
        .unwrap()
    };

    // instantiate the ctr DRBG with a derivation function
    (@instantiate_ctr_drbg_with_df $drbg:tt, $question:ident, $policy:ident) => {
        <impl_kat!(@drbg_type $drbg)>::new_with_df(
            &$question.entropy_input,
            &$question.nonce,
            &$question.personalization_string,
            $policy,
        )
        .unwrap()
    };

    // parse questions from the drbgvectors_no_reseed directory
    (@define_questions "drbgvectors_no_reseed", $test_file:literal) => {
        blobby::parse_into_structs!(
            include_bytes!(concat!("../assets/drbgvectors_no_reseed/", $test_file, ".blb"));
            #[define_struct]
            static QUESTIONS: &[Kat {
                entropy_input,
                nonce,
                personalization_string,
                additional_input_1,
                additional_input_2,
                returned_bits,
            }];
        );
    };

    // parse questions from the drbgvectors_pr_false directory
    (@define_questions "drbgvectors_pr_false", $test_file:literal) => {
        blobby::parse_into_structs!(
            include_bytes!(concat!("../assets/drbgvectors_pr_false/", $test_file, ".blb"));
            #[define_struct]
            static QUESTIONS: &[Kat {
                entropy_input,
                nonce,
                personalization_string,
                entropy_input_reseed,
                additional_input_reseed,
                additional_input_1,
                additional_input_2,
                returned_bits,
            }];
        );
    };

    // parse questions from the drbgvectors_pr_true directory
    (@define_questions "drbgvectors_pr_true", $test_file:literal) => {
        blobby::parse_into_structs!(
            include_bytes!(concat!("../assets/drbgvectors_pr_true/", $test_file, ".blb"));
            #[define_struct]
            static QUESTIONS: &[Kat {
                entropy_input,
                nonce,
                personalization_string,
                additional_input_1,
                entropy_input_pr_1,
                additional_input_2,
                entropy_input_pr_2,
                returned_bits,
            }];
        );
    };
}

// instantiate many KAT tests of a single class
macro_rules! impl_kat_many {
    (class = $test_class:tt, $($test_file:tt),+ $(,)?) => {
        $(
            impl_kat!(class = $test_class, $test_file);
        )*
    }
}

#[test]
#[cfg(any(feature = "sha1", feature = "sha2"))]
/// Test KAT values for Hash Drbg with no reseeding
fn test_hash_kat_no_reseed() {
    #[cfg(feature = "sha1")]
    impl_kat!(class = "drbgvectors_no_reseed", "Hash_SHA-1");

    #[cfg(feature = "sha2")]
    impl_kat_many!(
        class = "drbgvectors_no_reseed",
        "Hash_SHA-224",
        "Hash_SHA-256",
        "Hash_SHA-384",
        "Hash_SHA-512",
        "Hash_SHA-512_224",
        "Hash_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "sha1", feature = "sha2"))]
/// Test KAT values for Hash Drbg with explicit reseeding
fn test_hash_kat_pr_false() {
    #[cfg(feature = "sha1")]
    impl_kat!(class = "drbgvectors_pr_false", "Hash_SHA-1");

    #[cfg(feature = "sha2")]
    impl_kat_many!(
        class = "drbgvectors_pr_false",
        "Hash_SHA-224",
        "Hash_SHA-256",
        "Hash_SHA-384",
        "Hash_SHA-512",
        "Hash_SHA-512_224",
        "Hash_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "sha1", feature = "sha2"))]
/// Test KAT values for Hash Drbg with reseeding before extraction
fn test_hash_kat_pr_true() {
    #[cfg(feature = "sha1")]
    impl_kat!(class = "drbgvectors_pr_true", "Hash_SHA-1");

    #[cfg(feature = "sha2")]
    impl_kat_many!(
        class = "drbgvectors_pr_true",
        "Hash_SHA-224",
        "Hash_SHA-256",
        "Hash_SHA-384",
        "Hash_SHA-512",
        "Hash_SHA-512_224",
        "Hash_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
/// Test KAT values for HMAC Drbg with no reseeding
fn test_hmac_kat_no_reseed() {
    #[cfg(feature = "hmac-sha1")]
    impl_kat!(class = "drbgvectors_no_reseed", "HMAC_SHA-1");

    #[cfg(feature = "hmac-sha2")]
    impl_kat_many!(
        class = "drbgvectors_no_reseed",
        "HMAC_SHA-224",
        "HMAC_SHA-256",
        "HMAC_SHA-384",
        "HMAC_SHA-512",
        "HMAC_SHA-512_224",
        "HMAC_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
/// Test KAT values for HMAC Drbg with reseeding before extraction
fn test_hmac_kat_pr_false() {
    #[cfg(feature = "hmac-sha1")]
    impl_kat!(class = "drbgvectors_pr_false", "HMAC_SHA-1");

    #[cfg(feature = "hmac-sha2")]
    impl_kat_many!(
        class = "drbgvectors_pr_false",
        "HMAC_SHA-224",
        "HMAC_SHA-256",
        "HMAC_SHA-384",
        "HMAC_SHA-512",
        "HMAC_SHA-512_224",
        "HMAC_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "hmac-sha1", feature = "hmac-sha2"))]
/// Test KAT values for HMAC Drbg with reseeding before extraction
fn test_hmac_kat_pr_true() {
    #[cfg(feature = "hmac-sha1")]
    impl_kat!(class = "drbgvectors_pr_true", "HMAC_SHA-1");

    #[cfg(feature = "hmac-sha2")]
    impl_kat_many!(
        class = "drbgvectors_pr_true",
        "HMAC_SHA-224",
        "HMAC_SHA-256",
        "HMAC_SHA-384",
        "HMAC_SHA-512",
        "HMAC_SHA-512_224",
        "HMAC_SHA-512_256",
    );
}

#[test]
#[cfg(any(feature = "aes-ctr", feature = "tdea-ctr"))]
/// Test KAT values for CTR Drbg with no reseeding
fn test_ctr_kat_no_reseed() {
    #[cfg(feature = "tdea-ctr")]
    impl_kat_many!(
        class = "drbgvectors_no_reseed",
        "3KeyTDEA_no_df",
        "3KeyTDEA_use_df"
    );

    #[cfg(feature = "aes-ctr")]
    impl_kat_many!(
        class = "drbgvectors_no_reseed",
        "AES-128_no_df",
        "AES-128_use_df",
        "AES-192_no_df",
        "AES-192_use_df",
        "AES-256_no_df",
        "AES-256_use_df",
    );
}

#[test]
#[cfg(any(feature = "aes-ctr", feature = "tdea-ctr"))]
/// Test KAT values for CTR Drbg with reseeding before extraction
fn test_ctr_kat_pr_false() {
    #[cfg(feature = "tdea-ctr")]
    impl_kat_many!(
        class = "drbgvectors_pr_false",
        "3KeyTDEA_no_df",
        "3KeyTDEA_use_df"
    );

    #[cfg(feature = "aes-ctr")]
    impl_kat_many!(
        class = "drbgvectors_pr_false",
        "AES-128_no_df",
        "AES-128_use_df",
        "AES-192_no_df",
        "AES-192_use_df",
        "AES-256_no_df",
        "AES-256_use_df",
    );
}

#[test]
#[cfg(any(feature = "aes-ctr", feature = "tdea-ctr"))]
/// Test KAT values for CTR Drbg with reseeding before extraction
fn test_ctr_kat_pr_true() {
    #[cfg(feature = "tdea-ctr")]
    impl_kat_many!(
        class = "drbgvectors_pr_true",
        "3KeyTDEA_no_df",
        "3KeyTDEA_use_df"
    );

    #[cfg(feature = "aes-ctr")]
    impl_kat_many!(
        class = "drbgvectors_pr_true",
        "AES-128_no_df",
        "AES-128_use_df",
        "AES-192_no_df",
        "AES-192_use_df",
        "AES-256_no_df",
        "AES-256_use_df",
    );
}
