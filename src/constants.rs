pub use heapless::consts;

pub const PACKET_SIZE: usize = 64;

// 7609 bytes
pub const MESSAGE_SIZE: usize = PACKET_SIZE - 7 + 128 * (PACKET_SIZE - 5);

// #[repr(C)]
// pub struct InitPacket {
//     channel_id: u32,
//     command: u8,
//     length: u16,
//     data: [u8],
// }

// #[repr(C)]
// pub struct ContPacket {
//     channel_id: u32,
//     sequence: u16,
//     data: [u8],
// }

#[allow(non_camel_case_types)]
pub type ATTESTED_CREDENTIAL_DATA_LENGTH = consts::U512;
// not sure why i can't use `::to_usize()` here?
pub const ATTESTED_CREDENTIAL_DATA_LENGTH_BYTES: usize = 512;

#[allow(non_camel_case_types)]
pub type AUTHENTICATOR_DATA_LENGTH = consts::U512;
pub const AUTHENTICATOR_DATA_LENGTH_BYTES: usize = 512;

#[allow(non_camel_case_types)]
pub type COSE_KEY_LENGTH = consts::U256;
pub const COSE_KEY_LENGTH_BYTES: usize = 256;
