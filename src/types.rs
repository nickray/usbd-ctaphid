pub use heapless::{consts, String, Vec};
use serde::{Deserialize, Serialize};

use crate::{
    bytevec::ByteVec,
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

#[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize)]
pub struct AuthenticatorInfo {

    pub(crate) versions: Vec<String<consts::U8>, consts::U2>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) extensions: Option<Vec<String<consts::U11>, consts::U1>>,

    // #[serde(with = "serde_bytes")]
    // #[serde(serialize_with = "serde_bytes::serialize", deserialize_with = "serde_bytes::deserialize")]
    // #[serde(serialize_with = "serde_bytes::serialize")]
    // pub(crate) aaguid: Vec<u8, consts::U16>,
    pub(crate) aaguid: ByteVec<consts::U16>,

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
        let aaguid = ByteVec::<consts::U16>::from(zero_aaguid);

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

