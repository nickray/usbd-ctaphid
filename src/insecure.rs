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

// use core::convert::TryInto;
// use cortex_m_semihosting::hprintln;
use crate::{
    authenticator::{
        self,
        Error,
        Result,
    },
    bytes::Bytes,
    constants::{
        self,
        COSE_KEY_LENGTH,
        COSE_KEY_LENGTH_BYTES,
    },
    types::{
        AttestationObject,
        AttestedCredentialData,
        AuthenticatorData,
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
    aaguid: Bytes<consts::U16>,
    master_secret: [u8; 32],
}

impl InsecureRamAuthenticator {
}

impl Default for InsecureRamAuthenticator {
    fn default() -> Self {
        InsecureRamAuthenticator {
            aaguid: Bytes::from({
                let mut aaguid = Vec::<u8, consts::U16>::new();
                aaguid.extend_from_slice(b"AAGUID0123456789").unwrap();
                aaguid
            }),
            // Haaha. See why this is called an "insecure" authenticator? :D
            master_secret: [37u8; 32],
        }
    }
}

//// { 1: 2,  // kty (key type): tstr / int  [ 2 = EC2 = elliptic curve with x and y coordinate pair
////                                           1 = OKP = Octet Key Pair = for EdDSA
////          // kid, bstr
////   3: -7, // alg: tstr / int
//// [ 4:     // key_ops: tstr / int           1 = sign, 2 = verify, 3 = encrypt, 4 = decrypt, ...many more
////
////  // the curve: 1  = P-256
////  -1: 1,
////  // x-coordinate
////  -2: b'\xa0\xc3\x14\x06!\xefM\xcc\x06u\xf0\xf5v\x0bXa\xe6\xacm\x8d\xd9O`\xbd\x81\xf1\xe0_\x1a*\xdd\x9e',
////  // y-coordinate
////  -3: b'\xb4\xd4L\x94-\xbeVr\xe9C\x13u V\xf4t^\xe4.\xa2\x87I\xfe \xa4\xb0KY\x03\x00\x8c\x01'}
////
////  EdDSA
////   1: 1
////   3: -8,
////  -1: 6,
////  -2: public key bytes

fn serialize_salty_public_key(key: &salty::PublicKey) -> Bytes<COSE_KEY_LENGTH> {
    let mut buffer = [0u8; COSE_KEY_LENGTH_BYTES];

    let writer = serde_cbor::ser::SliceWrite::new(&mut buffer);
    let mut ser = serde_cbor::Serializer::new(writer);

    use serde::ser::SerializeMap;
    use serde::Serializer;
    let mut map = ser.serialize_map(Some(4)).unwrap();

    // kty (key type) 1 = OKP = Octet Key Pair = for EdDSA
    map.serialize_key(&1).unwrap();
    map.serialize_value(&1).unwrap();
    // alg: -8 = EdDSA
    map.serialize_key(&3).unwrap();
    map.serialize_value(&-8).unwrap();

    // the curve: 25519
    map.serialize_key(&-1).unwrap();
    map.serialize_value(&6).unwrap();
    // public key bytes
    map.serialize_key(&-2).unwrap();
    map.serialize_value(&{
        let mut bytes = Vec::<u8, consts::U32>::new();
        bytes.extend_from_slice(key.as_bytes()).unwrap();
        Bytes::from(bytes)
    }).unwrap();

    let writer = ser.into_inner();
    let size = writer.bytes_written();

    let mut bytes = Vec::<u8, COSE_KEY_LENGTH>::new();
    bytes.extend_from_slice(&buffer[..size]).unwrap();
    Bytes::from(bytes)
}

fn serialize_nisty_public_key(key: &nisty::PublicKey) -> Bytes<COSE_KEY_LENGTH> {
    let mut buffer = [0u8; COSE_KEY_LENGTH_BYTES];

    let writer = serde_cbor::ser::SliceWrite::new(&mut buffer);
    let mut ser = serde_cbor::Serializer::new(writer);

    use serde::ser::SerializeMap;
    use serde::Serializer;
    let mut map = ser.serialize_map(Some(5)).unwrap();

    // kty (key type) 2 = EC2 = elliptic curve with x/y coordinate pair
    map.serialize_key(&1).unwrap();
    map.serialize_value(&2).unwrap();
    // alg: -7 = ES256 = ECDSA with SHA-256
    map.serialize_key(&3).unwrap();
    map.serialize_value(&-7).unwrap();

    // the curve: P-256
    map.serialize_key(&-1).unwrap();
    map.serialize_value(&1).unwrap();
    // x-coordinate
    map.serialize_key(&-2).unwrap();
    map.serialize_value(&{
        let mut bytes = Vec::<u8, consts::U32>::new();
        bytes.extend_from_slice(&key.as_bytes()[..32]).unwrap();
        Bytes::from(bytes)
    }).unwrap();
    // y-coordinate
    map.serialize_key(&-3).unwrap();
    map.serialize_value(&{
        let mut bytes = Vec::<u8, consts::U32>::new();
        bytes.extend_from_slice(&key.as_bytes()[32..]).unwrap();
        Bytes::from(bytes)
    }).unwrap();

    let writer = ser.into_inner();
    let size = writer.bytes_written();

    let mut bytes = Vec::<u8, COSE_KEY_LENGTH>::new();
    bytes.extend_from_slice(&buffer[..size]).unwrap();
    Bytes::from(bytes)
}

impl authenticator::Api for InsecureRamAuthenticator {
    fn get_info(&self) -> AuthenticatorInfo {

        use core::str::FromStr;
        let mut versions = Vec::<String<consts::U8>, consts::U2>::new();
        versions.push(String::from_str("FIDO_2_0").unwrap()).unwrap();

        AuthenticatorInfo {
            versions,
            aaguid: self.aaguid.clone(),
            max_msg_size: Some(constants::MESSAGE_SIZE),
            ..AuthenticatorInfo::default()
        }
    }

    fn make_credential(&mut self, params: &MakeCredentialParameters) -> Result<AttestationObject> {
        // 0. Some general checks?

        // current solo does this
        if params.client_data_hash.len() != 32 {
            return Err(Error::InvalidLength);
        }

        // 1. Check excludeList
        // TODO

        // 2. check pubKeyCredParams algorithm is valid COSE identifier and supported
        let mut supported_algorithm = false;
        let mut eddsa = false;
        // let mut es256 = false;
        for param in params.pub_key_cred_params.iter() {
            match param.alg {
                -7 => { /*es256 = true;*/ supported_algorithm = true; },
                -8 => { eddsa = true; supported_algorithm = true; },
                _ => {},
            }
        }
        if !supported_algorithm {
            return Err(Error::UnsupportedAlgorithm);
        }

        // 3. check for known but unsupported options
        match &params.options {
            Some(ref options) => {
                if Some(true) == options.rk {
                    return Err(Error::UnsupportedOption);
                }
                if Some(true) == options.uv {
                    return Err(Error::UnsupportedOption);
                }
            },
            _ => {},
        }

        // 4. optionally, process extensions

        // 5-7. pinAuth handling
        // TODO

        // 8. request user presence (blink LED, or show user + rp on display if present)

        // 9. generate new key pair \o/
        //
        // We do it quick n' dirty here because YOLO
        let mut hash = salty::Sha512::new();
        hash.update(&self.master_secret);
        hash.update(&params.rp.id.as_str().as_bytes());
        hash.update(&params.user.id);
        let digest: [u8; 64] = hash.finalize();
        let seed = nisty::prehash(&digest);

        let credential_public_key = if eddsa {
            // prefer Ed25519
            let keypair = salty::Keypair::from(&seed);
            // hprintln!("public_key: {:?}", &keypair.public).ok();
            // let public_key_bytes = keypair.public.to_bytes();
            serialize_salty_public_key(&keypair.public)
        } else {
            // fallback NIST P-256
            let keypair = nisty::Keypair::generate_patiently(&seed);
            // hprintln!("public_key: {:?}", &keypair.public).ok();
            // TODO: use compressed public key?
            // keypair.public.to_bytes()[..32].try_into().unwrap()
            serialize_nisty_public_key(&keypair.public)
        };
        // hprintln!("serialized public_key: {:?}", &credential_public_key).ok();

        // 10. if `rk` option is set, attempt to store it
        // -> ruled out by above

        // 11. generate attestation statement.
        // For now, only "none" format, which has serialized "empty map" (0xa0) as its statement
        let fmt = String::<consts::U32>::from("none");
        let att_stmt = Bytes::<consts::U64>::from({
            let mut chars = Vec::<u8, consts::U64>::new();
            chars.push(0xa0).ok();
            chars
        });

        // return the attestation object
        // WARNING: another reason this is highly insecure, we return the seed
        // as credential ID ^^
        // TODO: do some AEAD based on xchacha20, later reject tampered/invalid credential IDs
        let mut credential_id = Bytes::<consts::U128>::new();
        credential_id.extend_from_slice(&seed).unwrap();

        let attested_credential_data = AttestedCredentialData {
            aaguid: self.aaguid.clone(),
            credential_id,
            credential_public_key,
        };

        // flags:
        //
        // USER_PRESENT = 0x01
        // USER_VERIFIED = 0x04
        // ATTESTED = 0x40
        // EXTENSION_DATA = 0x80
        let auth_data = AuthenticatorData {
            rp_id_hash: Bytes::<consts::U32>::from({
                let mut bytes = Vec::<u8, consts::U32>::new();
                bytes.extend_from_slice(&nisty::prehash(&params.rp.id.as_str().as_bytes())).unwrap();
                bytes
            }),
            flags: 0x40,
            // flags: 0x0,
            sign_count: 123,
            attested_credential_data: Some(attested_credential_data.serialize()),
            // attested_credential_data: None,
        };

        let attestation_object = AttestationObject {
            fmt,
            auth_data: auth_data.serialize(),
            att_stmt,
        };
        Ok(attestation_object)
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
