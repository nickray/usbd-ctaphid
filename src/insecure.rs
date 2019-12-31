//! WARNING: Using this needs a workaround due to
//! https://github.com/rust-lang/cargo/issues/5730
//!
//! The problem is that serde_cbor and bindgen's dependency rustc-hash
//! both use `byteorder`, but the latter activates the `std` feature,
//! breaking everything :/
//!
//! The workaround is to add the following in the application that actually uses this:
//!
//! ```ignore
//! [patch.crates-io]
//! rustc-hash = { git = "https://github.com/nickray/rustc-hash", branch = "nickray-remove-byteorder" }
//! ```
//!
//! # Goal:
//!
//! Here we implement a dumb FIDO2 device that just outputs
//! diagnostic messages using semihosting
//!
//! Maybe a better place is in a separate crate.
//!
//! Maybe also want to pull in dependencies like littlefs2, nisty, salty, ...
//!
//! Similar to littlefs2, the idea is to run test using this MVP implementation

use crate::{
    authenticator,
    bytes::Bytes,
    constants,
    types::{
        AuthenticatorInfo,
        MakeCredentialParameters,
    },
};

use heapless::{
    Vec,
    String,
    consts,
};

// use littlefs2::{
//     ram_storage,
//     // TODO: fix the macro in littlefs2 to not require these three imports
//     // Particularly the Result one is bad as it can clobber other things.
//     consts,
//     driver,
//     io::Result,
// };

// ram_storage!(tiny);

pub struct InsecureRamAuthenticator {
}

impl InsecureRamAuthenticator {
}

impl Default for InsecureRamAuthenticator {
    fn default() -> Self {
        InsecureRamAuthenticator {}
    }
}

impl authenticator::Api for InsecureRamAuthenticator {
    fn get_info(&self) -> AuthenticatorInfo {

        use core::str::FromStr;
        let mut versions = Vec::<String<consts::U8>, consts::U2>::new();
        versions.push(String::from_str("FIDO_2_0").unwrap()).unwrap();

        let mut aaguid = Vec::<u8, consts::U16>::new();
        aaguid.extend_from_slice(b"AAGUID0123456789").unwrap();

        AuthenticatorInfo {
            versions,
            aaguid: Bytes::from(aaguid),
            max_msg_size: Some(constants::MESSAGE_SIZE),
            ..AuthenticatorInfo::default()
        }
    }

    fn make_credential(&mut self, _params: &MakeCredentialParameters) -> authenticator::Credential {
        authenticator::Credential {}
    }
}

#[macro_export]
macro_rules! insecure_ram_authenticator {
    (api=$AuthenticatorApi:path, ctap_options=$CtapOptions:ty) => {
        struct InsecureRamAuthenticator {
        }

        impl InsecureRamAuthenticator {
        }

        impl $AuthenticatorApi for InsecureRamAuthenticator {
            fn get_info(&self) -> AuthenticatorInfo {

                AuthenticatorInfo {
                    versions: &["FIDO_2_0"], // &["U2F_V2", "FIDO_2_0"],
                    extensions: None, // Some(&["hmac-secret"]),
                    aaguid: b"AAGUID0123456789",
                    // options: None, // Some(CtapOptions::default()),
                    options: Some(<$CtapOptions>::default()),
                    // max_msg_size: Some(MESSAGE_SIZE),
                    max_msg_size: Some(7609),
                    pin_protocols: None, // Some(&[1]),
                };

            }
        }

    }
}
