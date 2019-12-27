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
};

/// The actual payload of given length is dealt with separately
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
struct Request {
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
    CompleteRequest,

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
    buffer: [u8; MESSAGE_SIZE],
    // expected sequence number of next continuation packet
    expected_sequence: u8,
    // number of bytes received of request payload
    received: usize,
    // // declared length of request payload
    // length: usize,
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
        let mut packet = [0u8; PACKET_SIZE];
        match self.read_endpoint.read(&mut packet) {
            Ok(PACKET_SIZE) => {},
            Ok(_) => {
                // error handling?
                // from spec: "Packets are always fixed size (defined by the endpoint and
                // HID report descriptors) and although all bytes may not be needed in a
                // particular packet, the full size always has to be sent.
                // Unused bytes SHOULD be set to zero."
                return;
            },
            // usb-device lists WouldBlock or BufferOverflow as possible errors.
            // both should not occur here, and we can't do anything anyway.
            // Err(UsbError::WouldBlock) => { return; },
            // Err(UsbError::BufferOverflow) => { return; },
            Err(_) => {
                return;
            },
        };

        let channel = u32::from_le_bytes(packet[..4].try_into().unwrap());
        let is_initialization = (packet[4] >> 7) != 0;

        if is_initialization {
            // case of initialization packet

            if !(self.state == State::Idle) {
                // TODO: should we buffer "busy errors" and send them?
                // vs. just failing silently
                return;
            }

            let command = match Command::try_from(packet[4]) {
                Ok(command) => command,
                Err(_) => { return; },
            };

            let request = Request {
                channel,
                command,
                length: u16::from_le_bytes(packet[5..7].try_into().unwrap()),
            };

            if request.length > MESSAGE_SIZE as u16 {
                // non-conforming client - we disregard it
                return;
            }

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
                self.state = State::CompleteRequest;
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
                match request.channel {
                    // broadcast channel ID - request for assignment
                    0xFFFF_FFFF => {
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

            // TODO: handle other requests
            _ => {},
        }
    }

}
