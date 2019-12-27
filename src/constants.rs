pub enum Command {
    // mandatory for CTAP1
    Ping = 0x01,
    Msg = 0x03,
    Init = 0x06,
    Error = 0x3f,

    // optional for CTAP1
    Wink = 0x08,
    Lock = 0x04,

    // mandatory for CTAP2
    Cbor = 0x10,
    Cancel = 0x11,
    KeepAlive = 0x3b,

    // vendor
    VendorFirst = 0x40,
    VendorLast = 0x7f,
}

#[repr(C)]
pub struct InitPacket {
    channel_id: u32,
    command: u8,
    length: u16,
    data: [u8],
}

#[repr(C)]
pub struct ContPacket {
    channel_id: u32,
    sequence: u16,
    data: [u8],
}
