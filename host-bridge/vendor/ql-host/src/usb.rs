// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT OR Apache-2.0

//! The QL interface of Passport Prime: a pair of bulk endpoints carrying one record per transfer,
//! which a short or zero length packet ends.

use std::{io, sync::Arc, time::Duration};

use rusb::{DeviceHandle, GlobalContext};

use crate::Transport;

const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

type Handle = Arc<DeviceHandle<GlobalContext>>;

impl Transport {
    /// A transport to the first Passport Prime on USB
    pub fn usb() -> io::Result<Transport> {
        const PASSPORT: (u16, u16) = (0x1307, 0x0165);
        const LEGACY_PASSPORT: (u16, u16) = (0x2c97, 0x0007);

        let mut handle = rusb::open_device_with_vid_pid(PASSPORT.0, PASSPORT.1)
            .or_else(|| rusb::open_device_with_vid_pid(LEGACY_PASSPORT.0, LEGACY_PASSPORT.1))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Passport Prime on USB"))?;
        let endpoints = find_ql_interface(&handle)?;
        // Fails when no kernel driver holds the interface, and where detaching isn't supported.
        handle.detach_kernel_driver(endpoints.interface).ok();
        handle.claim_interface(endpoints.interface).map_err(io::Error::other)?;

        let handle = Arc::new(handle);
        let (transport, link) = Transport::new(ql_invite_code::Transport::Usb);
        std::thread::spawn({
            let handle = handle.clone();
            move || write_records(&handle, endpoints.out, endpoints.max_packet_out, link.outgoing)
        });
        std::thread::spawn(move || read_records(&handle, endpoints.input, link.incoming));
        Ok(transport)
    }
}

struct Endpoints {
    interface: u8,
    out: u8,
    max_packet_out: usize,
    input: u8,
}

fn find_ql_interface(handle: &DeviceHandle<GlobalContext>) -> io::Result<Endpoints> {
    const CLASS: (u8, u8, u8) = (0xff, 0x51, 0x01);

    let config = handle.device().active_config_descriptor().map_err(io::Error::other)?;
    for descriptor in config.interfaces().flat_map(|interface| interface.descriptors()) {
        if (descriptor.class_code(), descriptor.sub_class_code(), descriptor.protocol_code()) != CLASS {
            continue;
        }
        let bulk = || {
            descriptor
                .endpoint_descriptors()
                .filter(|endpoint| endpoint.transfer_type() == rusb::TransferType::Bulk)
        };
        let out = bulk().find(|endpoint| endpoint.direction() == rusb::Direction::Out);
        let input = bulk().find(|endpoint| endpoint.direction() == rusb::Direction::In);
        if let (Some(out), Some(input)) = (out, input) {
            return Ok(Endpoints {
                interface: descriptor.interface_number(),
                out: out.address(),
                max_packet_out: usize::from(out.max_packet_size()),
                input: input.address(),
            });
        }
    }
    Err(io::Error::new(io::ErrorKind::NotFound, "Passport Prime has no QL interface"))
}

fn write_records(
    handle: &Handle,
    endpoint: u8,
    max_packet: usize,
    outgoing: async_channel::Receiver<Vec<u8>>,
) {
    while let Ok(record) = outgoing.recv_blocking() {
        if let Err(error) = handle.write_bulk(endpoint, &record, WRITE_TIMEOUT) {
            return log::error!("USB write failed: {error}");
        }
        // A record filling its last packet needs a zero length one to end the transfer.
        if record.len() % max_packet == 0 {
            if let Err(error) = handle.write_bulk(endpoint, &[], WRITE_TIMEOUT) {
                return log::error!("USB write failed: {error}");
            }
        }
    }
}

fn read_records(handle: &Handle, endpoint: u8, incoming: async_channel::Sender<Vec<u8>>) {
    const MAX_RECORD_LEN: usize = 8 * 1024;
    // Short, so that the thread notices soon that the session is gone.
    const READ_TIMEOUT: Duration = Duration::from_millis(500);

    let mut buffer = vec![0; MAX_RECORD_LEN];
    while !incoming.is_closed() {
        match handle.read_bulk(endpoint, &mut buffer, READ_TIMEOUT) {
            // A stray zero length packet carries no record.
            Ok(0) | Err(rusb::Error::Timeout) => {}
            Ok(length) => {
                if incoming.send_blocking(buffer[..length].to_vec()).is_err() {
                    return;
                }
            }
            Err(error) => return log::error!("USB read failed: {error}"),
        }
    }
}
