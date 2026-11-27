// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relays Passport Prime's QL USB interface to stdio, for a QL session that runs elsewhere (over
//! SSH). Each record crosses stdio as a 4-byte big-endian length and the record. The records are
//! QL's encrypted wire records: this process has no QL identity, no session keys and no QL code, so
//! it can't read or forge what it carries. USB handling follows KeyOS' ql-host `usb.rs`.

use std::{
    io::{self, Read, Write},
    sync::Arc,
    time::Duration,
};

use rusb::{DeviceHandle, GlobalContext};

const PASSPORT: (u16, u16) = (0x1307, 0x0165);
const QL_CLASS: (u8, u8, u8) = (0xff, 0x51, 0x01);
const MAX_RECORD_LEN: usize = 8 * 1024;
const MAX_FRAMED_RECORD: usize = 64 * 1024;
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_millis(500);

struct Endpoints {
    interface: u8,
    out: u8,
    max_packet_out: usize,
    input: u8,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ql-usb-relay: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let probe = std::env::args().any(|arg| arg == "--probe");
    let handle = rusb::open_device_with_vid_pid(PASSPORT.0, PASSPORT.1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Passport Prime on USB"))?;
    let endpoints = find_ql_interface(&handle)?;
    handle.detach_kernel_driver(endpoints.interface).ok();
    handle.claim_interface(endpoints.interface).map_err(io::Error::other)?;
    eprintln!(
        "ql-usb-relay: claimed Passport Prime QL interface {} (out {:#04x}, in {:#04x})",
        endpoints.interface, endpoints.out, endpoints.input
    );
    if probe {
        return Ok(());
    }
    let handle = Arc::new(handle);

    let reader = {
        let handle = handle.clone();
        std::thread::spawn(move || usb_to_stdout(&handle, endpoints.input))
    };
    // stdin closing (the session ended or SSH dropped) ends the relay.
    let result = stdin_to_usb(&handle, endpoints.out, endpoints.max_packet_out);
    drop(reader);
    result
}

fn stdin_to_usb(handle: &DeviceHandle<GlobalContext>, endpoint: u8, max_packet: usize) -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut record = Vec::new();
    loop {
        let mut length = [0; 4];
        match stdin.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_FRAMED_RECORD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "record too long"));
        }
        record.resize(length, 0);
        stdin.read_exact(&mut record)?;
        handle.write_bulk(endpoint, &record, WRITE_TIMEOUT).map_err(io::Error::other)?;
        // A record filling its last packet needs a zero length one to end the transfer.
        if record.len() % max_packet == 0 {
            handle.write_bulk(endpoint, &[], WRITE_TIMEOUT).map_err(io::Error::other)?;
        }
    }
}

fn usb_to_stdout(handle: &DeviceHandle<GlobalContext>, endpoint: u8) {
    let mut stdout = io::stdout().lock();
    let mut buffer = vec![0; MAX_RECORD_LEN];
    loop {
        match handle.read_bulk(endpoint, &mut buffer, READ_TIMEOUT) {
            Ok(0) | Err(rusb::Error::Timeout) => {}
            Ok(length) => {
                let written = stdout
                    .write_all(&(length as u32).to_be_bytes())
                    .and_then(|()| stdout.write_all(&buffer[..length]))
                    .and_then(|()| stdout.flush());
                if written.is_err() {
                    std::process::exit(0);
                }
            }
            Err(error) => {
                eprintln!("ql-usb-relay: USB read failed: {error}");
                std::process::exit(1);
            }
        }
    }
}

fn find_ql_interface(handle: &DeviceHandle<GlobalContext>) -> io::Result<Endpoints> {
    let config = handle.device().active_config_descriptor().map_err(io::Error::other)?;
    for descriptor in config.interfaces().flat_map(|interface| interface.descriptors()) {
        if (descriptor.class_code(), descriptor.sub_class_code(), descriptor.protocol_code()) != QL_CLASS {
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
