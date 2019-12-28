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
    Receiving(Request),
    // the request message is ready
    RequestPending,

    Sending(Response),

    // DataIn,
    // DataInZlp,
    // DataInLast,
    // CompleteIn(Request),
    // StatusOut,
    // CompleteOut,
    // DataOut(Request),
    // StatusIn,
    // Error,
}

pub struct Pipe<'alloc, Bus>
where Bus: UsbBus
{
    read_endpoint: EndpointOut<'alloc, Bus>,
    write_endpoint: EndpointIn<'alloc, Bus>,
    state: State,

    // shared between requests and responses, due to size
    buffer: [u8; MESSAGE_SIZE],

    last_channel: u32,

    // expected sequence number of next continuation packet
    expected_sequence: u8,
    // number of bytes received of request payload
    received: usize,
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
            expected_sequence: 0,
            received: 0,
            // length: 0,
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
                self.state = State::Receiving(request);
                self.expected_sequence = 0;
                self.received = PACKET_SIZE - 7;
                self.buffer[..self.received].copy_from_slice(&packet[7..]);
                // we're done... wait for next packet
                return;
            } else {
                // request fits in one packet
                self.state = State::RequestPending;
                // let payload = &packet[7..request.length as usize + 7];
                self.buffer[..request.length as usize].copy_from_slice(
                    &packet[7..request.length as usize + 7]);
                self.handle_request(request); //, payload);
                return;
            }
        } else {
            // case of continuation packet
            match self.state {
                State::Receiving(request) => {
                    let sequence = packet[4];
                    if sequence != self.expected_sequence {
                        // error handling?
                        return;
                    }
                    if channel != request.channel {
                        // error handling?
                        return;
                    }

                    let payload_length = request.length as usize;
                    if self.received + (PACKET_SIZE - 5) < payload_length {
                        // store received part of payload
                        self.expected_sequence += 1;
                        self.received += PACKET_SIZE - 5;
                        self.buffer[self.received..self.received + PACKET_SIZE - 5]
                            .copy_from_slice(&packet[5..]);
                        return;
                    } else {
                        // self.received = self.length;
                        self.state = State::RequestPending;
                        let missing = request.length as usize - self.received;
                        self.buffer[self.received..payload_length]
                            .copy_from_slice(&packet[5..5 + missing]);
                        // let payload = &self.buffer[..payload_length];
                        self.handle_request(request);//, payload);
                    }
                },
                _ => {
                    // unexpected continuation packet
                    return;
                },
            }
        }
    }

    fn handle_request(&mut self, request: Request) { //, payload: &[u8]) {
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
                            for element in self.buffer[17..].iter_mut() {
                                *element = 0;
                            }
                            self.state = State::Sending(response);
                            self.write_packet_if_necessary();
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
                for element in self.buffer[..].iter_mut() {
                    *element = 0;
                }
                self.state = State::Sending(response);
                self.write_packet_if_necessary();
            },

            Command::Cbor => {
                // self.handle_cbor(request.length);
                hprintln!("received CBOR!").ok();
                let data = &self.buffer[..request.length as usize];
                hprintln!("data: {:?}", data).ok();
                if data == &[4] {
                    hprintln!("authenticatorGetInfo").ok();
                    // status: 0 = success;
                    self.buffer[0] = 0;
                    // CBOR encoded reponse
                    // let encoder = CtapCborEncoder(&mut self.buffer[1..]);
                    // encoder.map(|encoder|
                    //     encoder.item(|encoder|
                    //         encoder.key(|encoder|
                    let buf = &mut self.buffer[1..];
                    // // map(6)
                    // let buf[0] = 0xa6;
                    // map(1)
                    buf[0] = 0xa1;
                    let buf = &mut buf[1..];

                        // unsigned(1)
                        buf[0] = 0x01;
                        let buf = &mut buf[1..];

                            // array(2)
                            buf[0] = 0x82;
                            let buf = &mut buf[1..];

                                // text(8)
                                buf[0] = 0x68;
                                let buf = &mut buf[1..];
                                buf[..8].copy_from_slice(b"FIDO_2_0");
                                let buf = &mut buf[8..];

                                // text(6)
                                buf[0] = 0x66;
                                let buf = &mut buf[1..];
                                buf[..6].copy_from_slice(b"U2F_V2");
                                let buf = &mut buf[6..];

                        // unsigned(3)
                        buf[0] = 0x03;
                        let buf = &mut buf[1..];

                            // text(16)
                            buf[0] = 0x70;
                            let buf = &mut buf[1..];
                            buf[..16].copy_from_slice(b"0123456789ABCDEF");
                            let buf = &mut buf[16..];


                    let response = Response {
                        channel: request.channel,
                        command: request.command,
                        length: 20 + 18,
                    };
                    for element in buf[..].iter_mut() {
                        *element = 0;
                    }
                    self.state = State::Sending(response);
                    self.write_packet_if_necessary();
                }
                self.state = State::Idle;
            }

            // TODO: handle other requests
            _ => {},
        }
    }

    // called from poll, and when a packet has been sent
    pub(crate) fn write_packet_if_necessary(&mut self) {
        match self.state {
            State::Sending(response) => {
                hprintln!("sending response {:?}", &response).ok();
                // multi-packet responses not implemented yet
                assert!(response.length < PACKET_SIZE as u16 - 7);
                let mut packet = [0u8; PACKET_SIZE];
                packet[..4].copy_from_slice(&response.channel.to_be_bytes());
                packet[4] = response.command as u8 | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());
                packet[7..7 + response.length as usize].copy_from_slice(
                    &self.buffer[..response.length as usize]);
                hprintln!("with data {:x?}", &self.buffer[..response.length as usize]).ok();
                let result = self.write_endpoint.write(&packet);
                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this should only happen when
                    },
                    Err(_) => {
                        panic!("unexpected error writing packet!");
                    },
                    Ok(PACKET_SIZE) => {
                        // goodie, this worked
                        self.state = State::Idle;
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
