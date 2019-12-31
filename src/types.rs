pub use heapless::{consts, String, Vec};
use serde::{Deserialize, Serialize};

use crate::{
    bytes::Bytes,
    constants::MESSAGE_SIZE,
};

/// CTAP CBOR is crazy serious about canonical format.
/// If you change the order here, for instance python-fido2
/// will no longer parse the entire authenticatorGetInfo
#[derive(Copy,Clone,Debug,Deserialize,Eq,PartialEq,Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CtapOptions {
    rk: bool,
    up: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    uv: Option<bool>,
    plat: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_pin: Option<bool>,
}

impl Default for CtapOptions {
    fn default() -> Self {
        Self {
            rk: false,
            up: true,
            uv: None,
            plat: false,
            client_pin: None,
        }
    }
}
                // Deserialized:
                // {1: b'-T\x18\xa8\xc1\xd3&\x90\xbf\x0f?\x11S/\x9f\xeeo\x8f\xde\xc8\xc7|\x82\xf3V\xdd\xc6\xe5\xce\x03\xe6k',
                //  2: {'id': 'example.org', 'name': 'example site'},
                //  3: {'id': b'they', 'name': 'example user'},
                //  4: [{'alg': -7, 'type': 'public-key'}],
                //  5: []}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct PublicKeyCredentialRpEntity {
    pub id: String<consts::U64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String<consts::U64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String<consts::U64>>,
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialUserEntity {
    pub id: Bytes<consts::U64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String<consts::U64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String<consts::U64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String<consts::U64>>,
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct PublicKeyCredentialParameters {
    pub alg: i32,
    #[serde(rename = "type")]
    pub key_type: String<consts::U10>,
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialDescriptor {
    #[serde(rename = "name")]
    pub key_type: String<consts::U10>,
    pub id: Bytes<consts::U64>,
    // https://w3c.github.io/webauthn/#enumdef-authenticatortransport
    // transports: ...
}

// TODO: this is a bit weird to model...
// Need to be able to "skip unknown keys" in deserialization
#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct AuthenticatorExtensions {}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct AuthenticatorOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uv: Option<bool>,
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MakeCredentialParameters {
    pub client_data_hash: Bytes<consts::U32>,
    pub rp: PublicKeyCredentialRpEntity,
    pub user: PublicKeyCredentialUserEntity,
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters, consts::U8>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor, consts::U16>>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub extensions: Option<AuthenticatorExtensions>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub options: Option<AuthenticatorOptions>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub pin_auth: Option<Bytes<consts::U16>>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub pin_protocol: Option<u32>,
}

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct AuthenticatorInfo {

    pub(crate) versions: Vec<String<consts::U8>, consts::U2>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extensions: Option<Vec<String<consts::U11>, consts::U1>>,

    // #[serde(with = "serde_bytes")]
    // #[serde(serialize_with = "serde_bytes::serialize", deserialize_with = "serde_bytes::deserialize")]
    // #[serde(serialize_with = "serde_bytes::serialize")]
    // pub(crate) aaguid: Vec<u8, consts::U16>,
    pub(crate) aaguid: Bytes<consts::U16>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<CtapOptions>,
    //
    // TODO: this is actually the constant MESSAGE_SIZE
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_msg_size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pin_protocols: Option<Vec<u8, consts::U1>>,

    // not in the CTAP spec, but see https://git.io/JeNxG
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_creds_in_list: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_cred_id_length: Option<usize>,

    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub(crate) transports: Option<&'l[u8]>,

    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub(crate) algorithms: Option<&'l[u8]>,
}

impl Default for AuthenticatorInfo {
    fn default() -> Self {
        let mut zero_aaguid = Vec::<u8, consts::U16>::new();
        zero_aaguid.resize_default(16).unwrap();
        let aaguid = Bytes::<consts::U16>::from(zero_aaguid);

        Self {
            versions: Vec::new(),
            extensions: None,
            aaguid: aaguid,
            // options: None,
            options: Some(CtapOptions::default()),
            max_msg_size: Some(MESSAGE_SIZE),
            pin_protocols: None,
            max_creds_in_list: None,
            max_cred_id_length: None,
            // transports: None,
            // algorithms: None,
        }
    }
}

// // TODO: add Default and builder
// #[derive(Clone,Debug,Eq,PartialEq,Serialize)]
// pub struct AuthenticatorInfo<'l> {
//     pub(crate) versions: &'l[&'l str],
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) extensions: Option<&'l[&'l str]>,
//     // #[serde(serialize_with = "serde_bytes::serialize")]
//     pub(crate) aaguid: &'l [u8],//; 16],
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) options: Option<CtapOptions>,
//     // TODO: this is actually the constant MESSAGE_SIZE
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_msg_size: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) pin_protocols: Option<&'l[u8]>,

//     // not in the CTAP spec, but see https://git.io/JeNxG
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_creds_in_list: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) max_cred_id_length: Option<usize>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) transports: Option<&'l[u8]>,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub(crate) algorithms: Option<&'l[u8]>,
// }

// pub enum Algorithm {
//     ES256,
//     EdDSA,
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let mut buffer = [0u8; 64];
        let writer = serde_cbor::ser::SliceWrite::new(&mut buffer);
        let mut ser = serde_cbor::Serializer::new(writer)
            .packed_format()
            .pack_starting_with(1)
            .pack_to_depth(1)
        ;
        let mut cdh = Vec::<u8, consts::U32>::new();
        cdh.extend_from_slice(b"1234567890ABCDEF").unwrap();
        Bytes::from(cdh).serialize(&mut ser).unwrap();

        // let writer = ser.into_inner();
        // let size = writer.bytes_written();
        // let buffer = writer.into_inner();

        // println!("serialized: {:#x?}", &buffer[..size]);
        // panic!("");
    }

    #[test]
    fn test_client_data_hash() {
        let mut minimal = [
            0x50u8, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, ];

        // This fails, but no good error message!
        // let mut client_data_hash: ByteVec<consts::U15> =

        let client_data_hash: Bytes<consts::U16> =
            serde_cbor::de::from_mut_slice(
                &mut minimal).unwrap();

        assert_eq!(client_data_hash, b"1234567890ABCDEF");
    }

    #[test]
    fn test_how_vec_dumps() {
        use core::str::FromStr;
        let cred_params = PublicKeyCredentialParameters {
            alg: -7,
            key_type: String::from_str("public-key").unwrap(),
        };
        let mut params: Vec<PublicKeyCredentialParameters, consts::U8> = Vec::new();
        params.push(cred_params).unwrap();

        let mut buffer = [0u8; 64];
        let writer = serde_cbor::ser::SliceWrite::new(&mut buffer);
        let mut ser = serde_cbor::Serializer::new(writer);
        params.serialize(&mut ser).unwrap();
        let writer = ser.into_inner();
        let size = writer.bytes_written();
        let buffer = writer.into_inner();
        assert_eq!(
            &[0x81u8,
                0xa2,
                    0x63, 0x61, 0x6c, 0x67, 0x26,
                    0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79,
            ], &buffer[..size]);

        use serde::de;
        let mut deserializer = serde_cbor::de::Deserializer::from_mut_slice(&mut buffer[..size]);
        //.packed_starts_with(1);
        let _deser: Vec<PublicKeyCredentialParameters, consts::U8> = de::Deserialize::deserialize(&mut deserializer).unwrap();
    }

    #[test]
    fn test_make_credential_deser() {
        let mut buffer = [
        0xa4u8,

        0x1,
        0x50, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,

        0x2,
        0xa1, 0x62, 0x69, 0x64, 0x73, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f,
        0x2f, 0x79, 0x61, 0x6d, 0x6e, 0x6f, 0x72, 0x64, 0x2e, 0x63, 0x6f, 0x6d,

        0x3,
        0xa1, 0x62, 0x69, 0x64, 0x47, 0x6e, 0x69, 0x63, 0x6b, 0x72, 0x61, 0x79,

        // fourth entry of struct (packed, offset 1 in ser/de)
        0x4,
            // array of...
            0x81,
                // struct (map)
                0xa2,
                    0x63, 0x61, 0x6c, 0x67, 0x26,
                    0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79,
        ];

        use serde::de;
        let mut deserializer = serde_cbor::de::Deserializer::from_mut_slice(&mut buffer).packed_starts_with(1);
        let _make_cred_params: MakeCredentialParameters = de::Deserialize::deserialize(&mut deserializer).unwrap();

        // let make_cred_params: MakeCredentialParameters =
        //     serde_cbor::de::from_mut_slice(
        //         &mut buffer).unwrap();
        // assert!(make_cred_params.client_data_hash.len() > 0);
        // assert!(make_cred_params.second_client_data_hash.is_none());
        // assert!(make_cred_params.third_client_data_hash.len() > 0);
    }
}
