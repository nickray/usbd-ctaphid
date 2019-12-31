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
use serde::{Deserialize, Serialize};
use usb_device::{
    bus::{UsbBus},
    endpoint::{EndpointAddress, EndpointIn, EndpointOut},
    UsbError,
    // Result as UsbResult,
};


use crate::{
    authenticator::Api as AuthenticatorApi,
    bytevec::ByteVec,
    constants::{
        // 7609
        MESSAGE_SIZE,
        // 64
        PACKET_SIZE,
    },
    types::{
        AuthenticatorInfo,
        CtapOptions,
    },
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

impl Response {
    pub fn from_request_and_size(request: Request, size: usize) -> Self {
        Self {
            channel: request.channel,
            command: request.command,
            length: size as u16,
        }
    }
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

/// the authenticator API, consisting of "operations"
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub enum Operation {
    MakeCredential,
    GetAssertion,
    GetNextAssertion,
    GetInfo,
    ClientPin,
    Reset,
    /// vendors are assigned the range 0x40..=0x7f for custom operations
    Vendor(VendorOperation),
}

impl Into<u8> for Operation {
    fn into(self) -> u8 {
        match self {
            Operation::MakeCredential => 0x01,
            Operation::GetAssertion => 0x02,
            Operation::GetNextAssertion => 0x08,
            Operation::GetInfo => 0x04,
            Operation::ClientPin => 0x06,
            Operation::Reset => 0x07,
            Operation::Vendor(operation) => operation.into(),
        }
    }
}

impl Operation {
    pub fn into_u8(self) -> u8 {
        self.into()
    }
}

/// Vendor CTAP2 operations, from 0x40 to 0x7f.
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub struct VendorOperation(u8);

impl VendorOperation {
    pub const FIRST: u8 = 0x40;
    pub const LAST: u8 = 0x7f;
}

impl TryFrom<u8> for VendorOperation {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Self, ()> {
        match from {
            // code if code >= Self::FIRST && code <= Self::LAST => Ok(VendorOperation(code)),
            code @ Self::FIRST..=Self::LAST => Ok(VendorOperation(code)),
            _ => Err(()),
        }
    }
}

impl Into<u8> for VendorOperation {
    fn into(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Operation {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Operation, ()> {
        match from {
            0x01 => Ok(Operation::MakeCredential),
            0x02 => Ok(Operation::GetAssertion),
            0x08 => Ok(Operation::GetNextAssertion),
            0x04 => Ok(Operation::GetInfo),
            0x06 => Ok(Operation::ClientPin),
            0x07 => Ok(Operation::Reset),
            code => Ok(Operation::Vendor(VendorOperation::try_from(code)?)),
            // _ => Err(()),
        }
    }
}

#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub enum Command {
    // mandatory for CTAP1
    Ping,
    Msg,
    Init,
    Error,

    // optional
    Wink,
    Lock,

    // mandatory for CTAP2
    Cbor,
    Cancel,
    KeepAlive,

    // vendor-assigned range from 0x40 to 0x7f
    Vendor(VendorCommand),
}

impl Command {
    pub fn into_u8(self) -> u8 {
        self.into()
    }
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
            code => Ok(Command::Vendor(VendorCommand::try_from(code)?)),
        }
    }
}

/// Vendor CTAPHID commands, from 0x40 to 0x7f.
#[derive(Copy,Clone,Debug,Eq,PartialEq)]
pub struct VendorCommand(u8);

impl VendorCommand {
    pub const FIRST: u8 = 0x40;
    pub const LAST: u8 = 0x7f;
}


impl TryFrom<u8> for VendorCommand {
    type Error = ();

    fn try_from(from: u8) -> core::result::Result<Self, ()> {
        match from {
            // code if code >= Self::FIRST && code <= Self::LAST => Ok(VendorCommand(code)),
            code @ Self::FIRST..=Self::LAST => Ok(VendorCommand(code)),
            // TODO: replace with Command::Unknown and infallible Try
            _ => Err(()),
        }
    }
}

impl Into<u8> for VendorCommand {
    fn into(self) -> u8 {
        self.0
    }
}

impl Into<u8> for Command {
    fn into(self) -> u8 {
        match self {
            Command::Ping => 0x01,
            Command::Msg => 0x03,
            Command::Init => 0x06,
            Command::Error => 0x3f,
            Command::Wink => 0x08,
            Command::Lock => 0x04,
            Command::Cbor => 0x10,
            Command::Cancel => 0x11,
            Command::KeepAlive => 0x3b,
            Command::Vendor(command) => command.into(),
        }
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(unused)]
enum State {
    Idle,

    // if request payload data is larger than one packet
    Receiving((Request, MessageState)),

    // the request message is ready, need to dispatch to "app"
    // Dispatching(Request)

    // the request message is dispatched to app, waiting for it to be processed
    Processing(Request),

    ResponsePending(Response),
    Sending((Response, MessageState)),
}

pub struct Pipe<'alloc, Authenticator, Bus>
where
    Authenticator: AuthenticatorApi,
    Bus: UsbBus,
{
    read_endpoint: EndpointOut<'alloc, Bus>,
    write_endpoint: EndpointIn<'alloc, Bus>,
    state: State,

    authenticator: &'alloc mut Authenticator,

    // shared between requests and responses, due to size
    buffer: [u8; MESSAGE_SIZE],

    // we assign channel IDs one by one, this is the one last assigned
    // TODO: move into "app"
    last_channel: u32,

}

impl<'alloc, Authenticator, Bus> Pipe<'alloc, Authenticator, Bus>
where
    Authenticator: AuthenticatorApi,
    Bus: UsbBus,
{
    pub(crate) fn new(
        read_endpoint: EndpointOut<'alloc, Bus>,
        write_endpoint: EndpointIn<'alloc, Bus>,
        authenticator: &'alloc mut Authenticator,
    ) -> Self
    {
        Self {
            read_endpoint,
            write_endpoint,
            state: State::Idle,
            authenticator,
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
        // hprintln!("got a packet!").ok();
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
        // hprintln!("channel {}", channel).ok();
        let is_initialization = (packet[4] >> 7) != 0;
        // hprintln!("is_initialization {}", is_initialization).ok();

        if is_initialization {
            // case of initialization packet

            if !(self.state == State::Idle) {
                // TODO: should we buffer "busy errors" and send them?
                // vs. just failing silently
                return;
            }

            let command_number = packet[4] & !0x80;
            // hprintln!("command number {}", command_number).ok();
            let command = match Command::try_from(command_number) {
                Ok(command) => command,
                // `solo ls` crashes here as it uses command 0x86
                Err(_) => { return; },
            };

            // can't actually fail
            let length = u16::from_be_bytes(packet[5..][..2].try_into().unwrap());

            let request = Request { channel, command, length };
            // hprintln!("request is {:?}", &request).ok();

            if length > MESSAGE_SIZE as u16 {
                // non-conforming client - we disregard it
                // TODO: error msg-too-long
                return;
            }

            // TODO: add some checks that request.length is OK.
            // e.g., CTAPHID_INIT should have payload of length 8.

            if length > PACKET_SIZE as u16 - 7 {
                // store received part of payload,
                // prepare for continuation packets
                self.buffer[..PACKET_SIZE - 7]
                    .copy_from_slice(&packet[7..]);
                self.state = State::Receiving((request, MessageState::default()));
                // we're done... wait for next packet
                return;
            } else {
                // request fits in one packet
                self.buffer[..length as usize]
                    .copy_from_slice(&packet[7..][..length as usize]);
                self.state = State::Processing(request);
                self.dispatch_request();
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
                        self.state = State::Processing(request);
                        self.dispatch_request();
                    }
                },
                _ => {
                    // unexpected continuation packet
                    return;
                },
            }
        }
    }

    fn dispatch_request(&mut self) {
        // TODO: can we guarantee only being called in this state?
        if let State::Processing(request) = self.state {
            // dispatch request further
            match request.command {
                Command::Init => {
                    hprintln!("command INIT!").ok();
                    // hprintln!("data: {:?}", &self.buffer[..request.length as usize]).ok();
                    match request.channel {
                        // broadcast channel ID - request for assignment
                        0xFFFF_FFFF => {
                            if request.length != 8 {
                                // error
                            } else {
                                self.last_channel += 1;
                                // hprintln!(
                                //     "assigned channel {}", self.last_channel).ok();
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
                            // TODO: "reset"
                        }
                    }
                },

                Command::Ping => {
                    hprintln!("received PING!").ok();
                    // hprintln!("data: {:?}", &self.buffer[..request.length as usize]).ok();
                    let response = Response::from_request_and_size(request, request.length as usize);
                    self.start_sending(response);
                },

                Command::Wink => {
                    hprintln!("received WINK!").ok();
                    // TODO: request.length should be zero
                    // TODO: callback "app"
                    let response = Response::from_request_and_size(request, 0);
                    self.start_sending(response);
                },

                Command::Cbor => {
                    hprintln!("command CBOR!").ok();
                    self.handle_cbor(request);
                },

                // TODO: handle other requests
                _ => {
                    hprintln!("unknown command {:?}", request.command).ok();
                },
            }
        }
    }

    fn handle_cbor(&mut self, request: Request) {
        let data = &self.buffer[..request.length as usize];
        // hprintln!("data: {:?}", data).ok();

        if data.len() < 1 {
            return;
        }

        let operation = match Operation::try_from(data[0]) {
            Ok(operation) => {
                hprintln!("Operation  {:?}", &operation).ok();
                operation
            },
            Err(_) => {
                hprintln!("Unknown operation code {:x?}", data[0]).ok();
                return;
            },
        };

        match operation {
            Operation::MakeCredential => {
                hprintln!("received authenticatorMakeCredential").ok();
                hprintln!("data = {:x?}", &data[1..]).ok();
                // Example: b'\xa5\x01X -T\x18\xa8\xc1\xd3&\x90\xbf\x0f?\x11S/\x9f\xeeo\x8f\xde\xc8\xc7|\x82\xf3V\xdd\xc6\xe5\xce\x03\xe6k\x02\xa2bidkexample.orgdnamelexample site\x03\xa2bidDtheydnamelexample user\x0 4\x81\xa2calg&dtypejpublic-key\x05\x80'
                //
                // Generated with: cl = solo.client.find_all()[0] and then intercepting
                // `request` in `fido2.ctap2.CTAP2.send_cbor`.
                // Deserialized:
                // {1: b'-T\x18\xa8\xc1\xd3&\x90\xbf\x0f?\x11S/\x9f\xeeo\x8f\xde\xc8\xc7|\x82\xf3V\xdd\xc6\xe5\xce\x03\xe6k',
                //  2: {'id': 'example.org', 'name': 'example site'},
                //  3: {'id': b'they', 'name': 'example user'},
                //  4: [{'alg': -7, 'type': 'public-key'}],
                //  5: []}
                //
                // Example: [
                //  a4, 1, 44, 31, 32, 33, 34, 2, 73, 68, 74, 74,
                //  70, 73, 3a, 2f, 2f, 79, 61, 6d, 6e, 6f, 72, 64,
                //  2e, 63, 6f, 6d, 3, 67, 6e, 69, 63, 6b, 72, 61,
                //  79, 4, 81, a2, 63, 61, 6c, 67, 62, 2d, 37, 64, 74, 79,
                //  70, 65, 6a, 70, 75, 62, 6c, 69, 63, 2d, 6b, 65, 79]
                //
                //  Can also generate with:
                //  dev = fido2.ctap2.CTAP2(next(fido2.hid.CtapHidDevice.list_devices()))
                //  dev.make_credential(
                //      b"1234",
                //      {"id": "https://yamnord.com"},
                //      {"id": "nickray"},
                //      [{"type": "public-key", "alg": -7}])
                //
                // Deserialized:
                // {1: b'1234',
                //  2: {'id': 'https://yamnord.com'},
                //  3: {'id': 'nickray'},
                //  4: [{'alg': -7, 'type': 'public-key'}]}
                //
                //  Actually...
                //  1 = clientDataHash = byte array, SHA-256 digest (--> 32 bytes)
                //  2 = PublicKeyCredentialRpEntity = { "id": "https://yamnord.com", ...optional }
                //  3 = PublicKeyCredentialUserEntity = { "id": "nickray", ...optional }
                //          e.g.: "displayName": "Nicolas Stalder"
                //  4 = sequence of CBOR maps consisting of pair
                //        - PublicKeyCredentialType: string
                //        - integer: algorithm from IANA COSE algorithms
                //          https://www.iana.org/assignments/cose/cose.xhtml#algorithms
                //      sorted descending by RP preference, we want to support:
                //        -7 = ES256 = ECDSA with SHA-256, picking NIST P-256 curve (curve 1)
                //        -8 = EdDSA, picking Ed25519 curve (curve 6)
                //      see fido2/cose.py
                //
                // TODO: deserialize CBOR to nice Rust types, call "app" via trait method
                // TODO: do we poll the app for processed result? does the app callback us?
                return;
            },

            Operation::GetInfo => {
                hprintln!("received authenticatorGetInfo").ok();

                let authenticator_info = self.authenticator.get_info();
                // hprintln!("authenticator_info = {:?}", &authenticator_info).ok();

                // status: 0  = success;
                self.buffer[0] = 0;
                // actual payload
                let writer = serde_cbor::ser::SliceWrite::new(&mut self.buffer[1..]);
                let mut ser = serde_cbor::Serializer::new(writer)
                    .packed_format()
                    .pack_starting_with(1)
                    .pack_to_depth(1)
                ;


                authenticator_info.serialize(&mut ser).unwrap();

                let writer = ser.into_inner();
                let size = 1 + writer.bytes_written();

                // let mut scratch = [0u8; 128];
                // let mut a: AuthenticatorInfo = serde_cbor::de::from_slice_with_scratch(
                //     &self.buffer[1..size], &mut scratch).unwrap()/
                // let mut a: AuthenticatorInfo = serde_cbor::de::from_mut_slice(
                //     &mut self.buffer[1..size]).unwrap()/

                // let mut scratch = [0u8; 128];
                // let authn: AuthenticatorInfo = serde_cbor::de::from_slice_with_scratch(
                //     &self.buffer[1..size], &mut scratch).unwrap();

                // hprintln!("using serde, wrote {} bytes: {:x?}",
                //           size, &self.buffer[..size]).ok();
                let response = Response::from_request_and_size(request, size);
                self.start_sending(response);
            },

            _ => {
                hprintln!("Operation {:?} not implemented", operation).ok();
                return;
            },
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
                // packet[4] = response.command.into() | 0x80u8;
                packet[4] = response.command.into_u8() | 0x80;
                packet[5..7].copy_from_slice(&response.length.to_be_bytes());

                let fits_in_one_packet = 7 + response.length as usize <= PACKET_SIZE;
                if fits_in_one_packet {
                    packet[7..][..response.length as usize]
                        .copy_from_slice( &self.buffer[..response.length as usize]);
                    self.state = State::Idle;
                } else {
                    packet[7..].copy_from_slice(&self.buffer[..PACKET_SIZE - 7]);
                }

                // try actually sending
                // hprintln!("attempting to write init packet {:?}, {:?}",
                //           &packet[..32], &packet[32..]).ok();
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
                let last_packet = 5 + remaining <= PACKET_SIZE;
                if last_packet {
                    packet[5..][..remaining].copy_from_slice(
                        &self.buffer[message_state.transmitted..][..remaining]);
                } else {
                    packet[5..].copy_from_slice(
                        &self.buffer[message_state.transmitted..][..PACKET_SIZE - 5]);
                }

                // try actually sending
                // hprintln!("attempting to write cont packet {:?}, {:?}",
                //           &packet[..32], &packet[32..]).ok();
                let result = self.write_endpoint.write(&packet);

                match result {
                    Err(UsbError::WouldBlock) => {
                        // fine, can't write try later
                        // this shouldn't happen probably
                        hprintln!("can't send seq {}, write endpoint busy",
                                  message_state.next_sequence).ok();
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
                            // DANGER! destructuring in the match arm copies out
                            // message state, so need to update state
                            self.state = State::Sending((response, message_state));
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
