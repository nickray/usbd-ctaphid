#![no_std]

pub mod constants;

use usb_device::{
    bus::{
        InterfaceNumber,
        UsbBus,
        UsbBusAllocator,
    },
    class::{
        ControlIn,
        ControlOut,
        UsbClass,
    },
    control,
    descriptor::{
        DescriptorWriter,
    },
    endpoint::{
        EndpointIn,
        EndpointOut,
    },
    Result as UsbResult,
};

/// Packet-level implementation of the CTAPHID protocol.
pub struct RawCtapHid<'bus, Bus: UsbBus> {
    interface: InterfaceNumber,
    read_endpoint: EndpointOut<'bus, Bus>,
    write_endpoint: EndpointIn<'bus, Bus>,
}

const PACKET_SIZE: u16 = 64;
const INTERRUPT_POLL_MILLISECONDS: u8 = 5;

impl <'alloc, Bus> RawCtapHid<'alloc, Bus>
where
	Bus: UsbBus
{
	pub fn new(allocate: &'alloc UsbBusAllocator<Bus>) -> Self {
        Self {
            interface: allocate.interface(),
            // 64 bytes, interrupt endpoint polled every 5 milliseconds
            read_endpoint: allocate.interrupt(PACKET_SIZE, INTERRUPT_POLL_MILLISECONDS),
            // PACKET_SIZE bytes, interrupt endpoint polled every INTERRUPT_POLL_MILLISECONDS milliseconds
            write_endpoint: allocate.interrupt(PACKET_SIZE, INTERRUPT_POLL_MILLISECONDS),
        }
	}

    pub fn read_packet(&mut self, data: &mut [u8]) -> UsbResult<usize> {
        self.read_endpoint.read(data)
    }

    pub fn write_packet(&mut self, data: &[u8]) -> UsbResult<usize> {
        self.write_endpoint.write(data)
    }
}

const HID_INTERFACE_CLASS: u8 = 0x03;

const INTERFACE_SUBCLASS_NONE: u8 = 0x0;
// const INTERFACE_SUBCLASS_BOOT: u8 = 0x1;

const INTERFACE_PROTOCOL_NONE: u8 = 0x0;
// const INTERFACE_PROTOCOL_KEYBOARD: u8 = 0x1;
// const INTERFACE_PROTOCOL_MOUSE: u8 = 0x2;

const HID_DESCRIPTOR: u8 = 0x21;
const HID_REPORT_DESCRIPTOR: u8 = 0x22;

const FIDO_HID_REPORT_DESCRIPTOR_LENGTH: usize = 34;
// cf. https://git.io/Jebh8
const FIDO_HID_REPORT_DESCRIPTOR: [u8; FIDO_HID_REPORT_DESCRIPTOR_LENGTH] = [
    0x06, 0xD0, 0xF1,  // Usage page (vendor defined): 0xF1D0A (FIDO_USAGE_PAGE)
    0x09, 0x01,        // Usage ID (vendor defined): 0x1 (FIDO_USAGE_CTAPHID)
    0xA1, 0x01,        // Collection (application)

    // The Input report
    0x09, 0x03,        // Usage ID - vendor defined: FIDO_USAGE_DATA_IN
    0x15, 0x00,        // Logical Minimum (0)
    0x26, 0xFF, 0x00,  // Logical Maximum (255)
    0x75, 0x08,        // Report Size (8 bits)
    0x95, PACKET_SIZE as u8, // Report Count (64 fields)
    0x81, 0x08,        // Input (Data, Variable, Absolute)

    // The Output report
    0x09, 0x04,        // Usage ID - vendor defined: FIDO_USAGE_DATA_OUT
    0x15, 0x00,        // Logical Minimum (0)
    0x26, 0xFF, 0x00,  // Logical Maximum (255)
    0x75, 0x08,        // Report Size (8 bits)
    0x95, PACKET_SIZE as u8, // Report Count (64 fields)
    0x91, 0x08,        // Output (Data, Variable, Absolute)

    0xC0,              // EndCollection
];

// see hid1_11.pdf, section 7.2, p. 50
#[derive(Copy,Clone,Eq,Debug,PartialEq)]
pub enum ClassRequests {
    /// mandatory, allow host to receive report via control pipe.
    /// intention: initialization
    GetReport = 0x1,
    GetIdle = 0x2,
    /// only boot subclass
    GetProtocol = 0x3,
    SetReport = 0x9,
    SetIdle = 0xA,
    /// only boot subclass
    SetProtocol = 0xB,
}

impl<'alloc, Bus> UsbClass<Bus> for RawCtapHid<'alloc, Bus>
where
    Bus: UsbBus
{
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter) -> UsbResult<()> {

        writer.interface(
            self.interface,
            HID_INTERFACE_CLASS,
            INTERFACE_SUBCLASS_NONE,
            INTERFACE_PROTOCOL_NONE,
        )?;

        // big-endian u16
        writer.write(HID_DESCRIPTOR, &[
            0x11, 0x01, // bcdHID
            0x00, // country code: universal
            0x01, // number of HID report descriptors
            HID_REPORT_DESCRIPTOR, // 1st HID report descriptor type
            FIDO_HID_REPORT_DESCRIPTOR_LENGTH as u8, 0x00, // 1st HID report descriptor length in bytes as u16-be
        ])?;

        writer.endpoint(&self.read_endpoint)?;
        writer.endpoint(&self.write_endpoint)?;

        Ok(())
    }

    fn control_out(&mut self, xfer: ControlOut<Bus>) {
        let req = xfer.request();

        if req.request_type == control::RequestType::Class
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.interface) as u16
        {
            match req.request {
                // SetIdle (0xA)
                // duration = upper byte of wValue
                // repot ID = lower byte of wValue
                // happens during enumeration with wValue = 0x0000,
                //
                // tells device to NAK any polls on interrupt IN
                // while its current report remains unchanged
                r if r == ClassRequests::SetIdle as u8 => {
                    xfer.accept().ok();
                },
                _ => (),
            };
        }
    }

    fn control_in(&mut self, xfer: ControlIn<Bus>) {
        let req = xfer.request();

        if req.request_type == control::RequestType::Standard
            && req.recipient == control::Recipient::Interface
            && req.index == u8::from(self.interface) as u16
        {
            match req.request {
                // GetDescriptor (0x6),
                // wValue: 0x2200,
                // wIndex: 0x0,
                // wLength: 0x22, (34 bytes)
                control::Request::GET_DESCRIPTOR => {
                    xfer.accept(|data| {
                        assert!(data.len() >= FIDO_HID_REPORT_DESCRIPTOR_LENGTH);
                        data[..FIDO_HID_REPORT_DESCRIPTOR_LENGTH].copy_from_slice(&FIDO_HID_REPORT_DESCRIPTOR);
                        Ok(FIDO_HID_REPORT_DESCRIPTOR_LENGTH)
                    }).ok();
                },
                _ => (),
            }
        }
    }

}
