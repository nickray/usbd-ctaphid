/*!
The CTAP protocol is a series of atomic *transactions*, which consist
of a *request* message followed by a *response* message.

Messages may spread over multiple *packets*, starting with
an *initialization* packet, followed by zero or more *continuation* packets.

In the case of multiple clients, the first to get through its initialization
packet in device idle state locks the device for other channels (they will
receive busy errors).

No state is maintained between transactions.
*/

use core::convert::TryInto;
use core::convert::TryFrom;

use cortex_m_semihosting::hprintln;

use crate::{
    constants::{
        // 7609
        MESSAGE_SIZE,
        // 64
        PACKET_SIZE,
    },
};

use usb_device::{
    bus::{UsbBus},
    endpoint::{EndpointAddress, EndpointIn, EndpointOut},
    UsbError,
    // Result as UsbResult,
};

/// The actual payload of given length is dealt with separately
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
struct Request {
    channel: u32,
    command: Command,
    length: u16,
}

/// The actual payload of given length is dealt with separately
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
struct Response {
    channel: u32,
    command: Command,
    length: u16,
}

#[derive(Copy,Clone,Debug,Eq,PartialEq)]
struct MessageState {
    // sequence number of next continuation packet
    next_sequence: u8,
    // number of bytes of message payload transmitted so far
    transmitted: usize,
}

impl Default for MessageState {
    fn default() -> Self {
        Self {
            next_sequence: 0,
            transmitted: PACKET_SIZE - 7,
        }
    }
}

impl MessageState {
    // update state due to receiving a full new continuation packet
    pub fn absorb_packet(&mut self) {
        self.next_sequence += 1;
        self.transmitted += PACKET_SIZE - 5;
    }
}

#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub enum Command {
    // mandatory for CTAP1
    Ping = 0x01,
    Msg = 0x03,
    Init = 0x06,
    Error = 0x3f,

    // optional
    Wink = 0x08,
    Lock = 0x04,

    // mandatory for CTAP2
    Cbor = 0x10,
    Cancel = 0x11,
    KeepAlive = 0x3b,

    // vendor
    #[allow(dead_code)]
    VendorFirst = 0x40,
    #[allow(dead_code)]
    VendorLast = 0x7f,
}

impl TryFrom<u8> for Command {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Command, ()> {
        match from {
            0x01 => Ok(Command::Ping),
            0x03 => Ok(Command::Msg),
            0x06 => Ok(Command::Init),
            0x3f => Ok(Command::Error),
            0x08 => Ok(Command::Wink),
            0x04 => Ok(Command::Lock),
            0x10 => Ok(Command::Cbor),
            0x11 => Ok(Command::Cancel),
            0x3b => Ok(Command::KeepAlive),
            _ => Err(()),
        }
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
enum State {
    Idle,

    // if request payload data is larger than one packet
    Receiving((Request, MessageState)),

    // the request message is ready, waiting for processing
    RequestPending(Request),

    ResponsePending(Response),
    Sending((Response, MessageState)),
}

pub struct Pipe<'alloc, Bus>
where Bus: UsbBus
{
    read_endpoint: EndpointOut<'alloc, Bus>,
    write_endpoint: EndpointIn<'alloc, Bus>,
    state: State,

    // shared between requests and responses, due to size
    buffer: [u8; MESSAGE_SIZE],

    // we assign channel IDs one by one, this is the one last assigned
    last_channel: u32,

}

impl<'alloc, Bus> Pipe<'alloc, Bus>
where Bus: UsbBus
{
    pub(crate) fn new(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
    ) -> Self
    {
        Self {
            read_endpoint,
            write_endpoint,
            state: State::Idle,
            buffer: [0u8; MESSAGE_SIZE],
            last_channel: 0,
        }
    }

    pub fn read_address(&self) -> EndpointAddress {
        self.read_endpoint.address()
    }

    pub fn write_address(&self) -> EndpointAddress {
        self.write_endpoint.address()
    }

    // used to generate the configuration descriptors
    pub(crate) fn read_endpoint(&self) -> &EndpointOut<'alloc, Bus> {
        &self.read_endpoint
    }

    // used to generate the configuration descriptors
    pub(crate) fn write_endpoint(&self) -> &EndpointIn<'alloc, Bus> {
        &self.write_endpoint
    }

    pub(crate) fn read_and_handle_packet(&mut self) {
        hprintln!("got a packet!").ok();
        let mut packet = [0u8; PACKET_SIZE];
        match self.read_endpoint.read(&mut packet) {
            Ok(PACKET_SIZE) => {},
            Ok(size) => {
                // error handling?
                // from spec: "Packets are always fixed size (defined by the endpoint and
                // HID report descriptors) and although all bytes may not be needed in a
                // particular packet, the full size always has to be sent.
                // Unused bytes SHOULD be set to zero."
                hprintln!("OK but size {}", size).ok();
                return;
            },
            // usb-device lists WouldBlock or BufferOverflow as possible errors.
            // both should not occur here, and we can't do anything anyway.
            // Err(UsbError::WouldBlock) => { return; },
            // Err(UsbError::BufferOverflow) => { return; },
            Err(error) => {
                hprintln!("error no {}", error as i32).ok();
                return;
            },
        };

        let channel = u32::from_be_bytes(packet[..4].try_into().unwrap());
        hprintln!("channel {}", channel).ok();
        let is_initialization = (packet[4] >> 7) != 0;
        hprintln!("is_initialization {}", is_initialization).ok();

        if is_initialization {
            // case of initialization packet

            if !(self.state == State::Idle) {
                // TODO: should we buffer "busy errors" and send them?
                // vs. just failing silently
                return;
            }

            let command_number = packet[4] & !0x80;
            hprintln!("command number {}", command_number).ok();
            let command = match Command::try_from(command_number) {
                Ok(command) => command,
                // `solo ls` crashes here as it uses command 0x86
                Err(_) => { return; },
            };

            let request = Request {
                channel,
                command,
                // can't actually fail
                length: u16::from_be_bytes(packet[5..7].try_into().unwrap()),
            };

            hprintln!("request is {:?}", &request).ok();

            if request.length > MESSAGE_SIZE as u16 {
                // non-conforming client - we disregard it
                return;
            }

            // TODO: add some checks that request.length is OK.
            // e.g., CTAPHID_INIT should have payload of length 8.

            if request.length > PACKET_SIZE as u16 - 7 {
                // store received part of payload,
                // prepare for continuation packets
                self.buffer[..PACKET_SIZE - 7].copy_from_slice(&packet[7..]);
                self.state = State::Receiving((request, MessageState::default()));
                // we're done... wait for next packet
                return;
            } else {
                // request fits in one packet
                self.buffer[..request.length as usize].copy_from_slice(
                    &packet[7..][..request.length as usize]);
                self.state = State::RequestPending(request);
                self.handle_request();
                return;
            }
        } else {
            // case of continuation packet
            match self.state {
                State::Receiving((request, mut message_state)) => {
                    let sequence = packet[4];
                    if sequence != message_state.next_sequence {
                        // error handling?
                        return;
                    }
                    if channel != request.channel {
                        // error handling?
                        return;
                    }

                    let payload_length = request.length as usize;
                    if message_state.transmitted + (PACKET_SIZE - 5) < payload_length {
                        // store received part of payload
                        self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        message_state.absorb_packet();
                        return;
                    } else {
                        let missing = request.length as usize - message_state.transmitted;
                        self.buffer[message_state.transmitted..payload_length]
                            .copy_from_slice(&packet[5..][..missing]);
                        self.state = State::RequestPending(request);
                        self.handle_request();
                    }
                },
                _ => {
                    // unexpected continuation packet
                    return;
                },
            }
        }
    }

    fn handle_request(&mut self) {
        if let State::RequestPending(request) = self.state {
            // dispatch request further
            match request.command {
                Command::Init => {
                    hprintln!("received INIT!").ok();
                    hprintln!("data: {:?}", &self.buffer[..request.length as usize]).ok();
                    match request.channel {
                        // broadcast channel ID - request for assignment
                        0xFFFF_FFFF => {
                            if request.length != 8 {
                                // error
                            } else {
                                self.last_channel += 1;
                                hprintln!(
                                    "assigned channel {}", self.last_channel).ok();
                                let _nonce = &self.buffer[..8];
                                let response = Response {
                                    channel: 0xFFFF_FFFF,
                                    command: request.command,
                                    length: 17,
                                };

                                self.buffer[8..12].copy_from_slice(&self.last_channel.to_be_bytes());
                                // CTAPHID protocol version
                                self.buffer[12] = 2;
                                // major device version number
                                self.buffer[13] = 0;
                                // minor device version number
                                self.buffer[14] = 0;
                                // build device version number
                                self.buffer[15] = 0;
                                // capabilities flags
                                // 0x1: implements WINK
                                // 0x4: implements CBOR
                                // 0x8: does not implement MSG
                                // self.buffer[16] = 0x01 | 0x08;
                                self.buffer[16] = 0x01 | 0x04;
                                self.start_sending(response);
                            }
                        },
                        0 => {
                            // this is an error / reserved number
                        },
                        _ => {
                            // this is assumedly the active channel,
                            // already allocated to a client
                        }
                    }
                },

                Command::Ping => {
                    hprintln!("received PING!").ok();
                    hprintln!("data: {:?}", &self.buffer[..request.length as usize]).ok();
                    self.state = State::Idle;
                },

                Command::Wink => {
                    hprintln!("received WINK!").ok();
                    hprintln!("data: {:?}", &self.buffer[..request.length as usize]).ok();
                    let response = Response {
                        channel: request.channel,
                        command: request.command,
                        length: 0,
                    };
                    self.start_sending(response);
                },

                Command::Cbor => {
                    // self.handle_cbor(request.length);
                    hprintln!("received CBOR!").ok();
                    let data = &self.buffer[..request.length as usize];
                    hprintln!("data: {:?}", data).ok();
                    if data == &[4] {
                        hprintln!("authenticatorGetInfo").ok();

                        use serde::ser::Serializer;
                        use serde::ser::SerializeMap;

                        let writer = serde_cbor::ser::SliceWrite::new(&mut self.buffer[..]);
                        let mut ser = serde_cbor::Serializer::new(writer);//.packed_format();

                        // status: 0 = success
                        ser.serialize_u8(0).unwrap();

                        // now the actual CBOR payload
                        let mut map = ser.serialize_map(Some(2)).unwrap();

                        // versions
                        map.serialize_key(&1u8).unwrap();
                        // TODO: what would be the syntax to have an array as value,
                        // and e.g. write the supported versions individually, and
                        // hence more easily configurably?
                        map.serialize_value(&["FIDO_2_0", "U2F_V2"]).unwrap();

                        // extensions
                        map.serialize_key(&2u8).unwrap();
                        map.serialize_value(&["hmac-secret"]).unwrap();

                        // aaguid
                        map.serialize_key(&3u8).unwrap();
                        map.serialize_value("AAGUID0123456789").unwrap();
                        // let mut submap = ser.serialize_map(Some(1)).unwrap();
                        // submap.serialize_key(&4u8).unwrap();
                        // submap.serialize_value(&5u8).unwrap();

                        // options
                        // map.serialize_key(&4u8).unwrap();

                        // maxMsgSize
                        map.serialize_key(&5u8).unwrap();
                        map.serialize_value(&MESSAGE_SIZE).unwrap();

                        // pinProtocols
                        map.serialize_key(&6).unwrap();
                        map.serialize_value(&[1]).unwrap();

                        // let _: () = map.end().unwrap();

                        let writer = ser.into_inner();
                        let size = writer.bytes_written();
                        // hprintln!("using serde, wrote {} bytes: {:x?}", size, &self.buffer[..size]).ok();

                        let response = Response {
                            channel: request.channel,
                            command: request.command,
                            length: size as u16,
                        };
                        self.start_sending(response);
                    }
                }

                // TODO: handle other requests
                _ => {},
            }
        }
    }

    fn start_sending(&mut self, response: Response) {
        self.state = State::ResponsePending(response);
        self.maybe_write_packet();
    }

    // called from poll, and when a packet has been sent
    pub(crate) fn maybe_write_packet(&mut self) {
        match self.state {
            State::ResponsePending(response) => {

                // zeros leftover bytes
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = response.command as u8 | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());

                let fits_in_one_packet = response.length as usize <= PACKET_SIZE - 7;
                if fits_in_one_packet {
                    packet[7..][..response.length as usize].copy_from_slice(
                        &self.buffer[..response.length as usize]);
                    self.state = State::Idle;
                } else {
                    packet[7..].copy_from_slice(&self.buffer[..PACKET_SIZE - 7]);
                }

                // try actually sending
                let result = self.write_endpoint.write(&packet);

                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this shouldn't happen probably
                    },
                    Err(_) => {
                        panic!("unexpected error writing packet!");
                    },
                    Ok(PACKET_SIZE) => {
                        // goodie, this worked
                        if fits_in_one_packet {
                            self.state = State::Idle;
                            // hprintln!("StartSent {} bytes, idle again", response.length).ok();
                        } else {
                            self.state = State::Sending((response, MessageState::default()));
                            // hprintln!(
                            //     "StartSent {} of {} bytes, waiting to send again",
                            //     PACKET_SIZE - 7, response.length).ok();
                            // hprintln!("State: {:?}", &self.state).ok();
                        }
                    },
                    Ok(_) => {
                        panic!("unexpected size writing packet!");
                    },
                };
            },

            State::Sending((response, mut message_state)) => {
                // hprintln!("in StillSending").ok();
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = message_state.next_sequence;

                let sent = message_state.transmitted;
                let remaining = response.length as usize - sent;
                let last_packet = remaining <= PACKET_SIZE - 5;
                if last_packet {
                    packet[5..][..remaining].copy_from_slice(
                        &self.buffer[message_state.transmitted..response.length as usize]);
                } else {
                    packet[5..].copy_from_slice(
                        &self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]);
                }

                // try actually sending
                let result = self.write_endpoint.write(&packet);

                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this shouldn't happen probably
                        hprintln!("can't send, write endpoint busy").ok();
                    },
                    Err(_) => {
                        panic!("unexpected error writing packet!");
                    },
                    Ok(PACKET_SIZE) => {
                        // goodie, this worked
                        if last_packet {
                            self.state = State::Idle;
                        } else {
                            message_state.absorb_packet();
                        }
                    },
                    Ok(_) => {
                        panic!("unexpected size writing packet!");
                    },
                };
            },

            // nothing to send
            _ => {
            },
        }
    }
}
