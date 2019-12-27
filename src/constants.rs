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
