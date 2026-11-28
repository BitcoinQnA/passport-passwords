// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Relays Passport Prime's QL USB interface to a QL session that runs elsewhere. Each record
//! crosses the link as a 4-byte big-endian length and the record. The records are QL's encrypted
//! wire records: this process has no QL identity, no session keys and no QL code, so it can't read
//! or forge what it carries. USB handling follows KeyOS' ql-host `usb.rs`.
//!
//! The session end can be this process's stdio (for example when reached over SSH) or an outbound
//! TCP connection (`--connect host:port`). The laptop always dials out; it never listens. When the
//! box is not reachable on the tailnet, both sides dial Jarvis and `ql-byte-splice.py` joins the
//! two connections. Jarvis forwards opaque bytes only.
//!
//! On Windows, KeyOS already advertises this interface as WinUSB (Microsoft OS 2.0, GUID
//! {167F35F9-05C2-4AC7-96B3-D30C1020627F}), so Windows should bind a driver without a third-party
//! installer. Stdio is set to binary mode so record framing is not rewritten.

use std::{
    io::{self, Read, Write},
    net::TcpStream,
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
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);
const DIAL_TEST: &[u8] = b"ql-usb-relay-dial-test";

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
    set_stdio_binary();
    let mut probe = false;
    let mut list = false;
    let mut dial_only = false;
    let mut connect = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--probe" => probe = true,
            "--list" => list = true,
            "--dial-only" => dial_only = true,
            "--connect" => {
                connect = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--connect needs host:port")
                })?);
            }
            "-h" | "--help" => {
                eprint_usage();
                return Ok(());
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
    }
    if list {
        return list_devices();
    }
    if dial_only {
        let address = connect.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "--dial-only needs --connect host:port",
            )
        })?;
        return dial_test(&address);
    }

    let handle = rusb::open_device_with_vid_pid(PASSPORT.0, PASSPORT.1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Passport Prime on USB"))?;
    let endpoints = find_ql_interface(&handle)?;
    handle.detach_kernel_driver(endpoints.interface).ok();
    handle
        .claim_interface(endpoints.interface)
        .map_err(io::Error::other)?;
    eprintln!(
        "ql-usb-relay: claimed Passport Prime QL interface {} (out {:#04x}, in {:#04x})",
        endpoints.interface, endpoints.out, endpoints.input
    );
    if probe {
        return Ok(());
    }
    let handle = Arc::new(handle);

    if let Some(address) = connect {
        let stream = dial(&address)?;
        let incoming = stream.try_clone()?;
        let outgoing = stream;
        let reader = {
            let handle = handle.clone();
            std::thread::spawn(move || usb_to_writer(&handle, endpoints.input, outgoing))
        };
        let result = reader_to_usb(&handle, endpoints.out, endpoints.max_packet_out, incoming);
        drop(reader);
        return result;
    }

    let reader = {
        let handle = handle.clone();
        std::thread::spawn(move || usb_to_writer(&handle, endpoints.input, io::stdout().lock()))
    };
    // stdin closing (the session ended or SSH dropped) ends the relay.
    let result = reader_to_usb(
        &handle,
        endpoints.out,
        endpoints.max_packet_out,
        io::stdin().lock(),
    );
    drop(reader);
    result
}

fn eprint_usage() {
    eprintln!(
        "ql-usb-relay: moves opaque QL records between Passport Prime's QL USB interface and a session\n\
         usage: ql-usb-relay [--list | --probe | --dial-only --connect host:port | --connect host:port]\n\
           --list                   list USB devices and Prime's QL interface, without claiming it\n\
           --probe                  claim the QL interface and exit\n\
           --connect host:port      dial out and carry records over that connection (does not listen)\n\
           --dial-only --connect    check the outbound path only: no USB, no Prime prompt"
    );
}

fn set_stdio_binary() {
    #[cfg(windows)]
    {
        extern "C" {
            fn _setmode(fd: i32, mode: i32) -> i32;
        }
        const O_BINARY: i32 = 0x8000;
        unsafe {
            _setmode(0, O_BINARY);
            _setmode(1, O_BINARY);
        }
    }
}

fn dial(address: &str) -> io::Result<TcpStream> {
    let stream =
        TcpStream::connect_timeout(&address.parse().map_err(io::Error::other)?, DIAL_TIMEOUT)?;
    stream.set_nodelay(true)?;
    eprintln!("ql-usb-relay: connected to {address}");
    Ok(stream)
}

/// Sends one framed test record and expects the same bytes back. Does not open USB.
fn dial_test(address: &str) -> io::Result<()> {
    let mut stream = dial(address)?;
    stream.set_read_timeout(Some(DIAL_TIMEOUT))?;
    stream.write_all(&(DIAL_TEST.len() as u32).to_be_bytes())?;
    stream.write_all(DIAL_TEST)?;
    stream.flush()?;
    let mut length = [0; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length != DIAL_TEST.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("dial-test reply was {length} bytes"),
        ));
    }
    let mut record = vec![0; length];
    stream.read_exact(&mut record)?;
    if record != DIAL_TEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dial-test reply did not match",
        ));
    }
    eprintln!("ql-usb-relay: dial-test ok, the outbound path to the box is open");
    Ok(())
}

fn list_devices() -> io::Result<()> {
    let devices = rusb::devices().map_err(io::Error::other)?;
    let mut found_prime = false;
    let mut found_ql = false;
    for device in devices.iter() {
        let desc = device.device_descriptor().map_err(io::Error::other)?;
        let vid = desc.vendor_id();
        let pid = desc.product_id();
        let mut name = String::new();
        if let Ok(handle) = device.open() {
            if let Ok(langs) = handle.read_languages(Duration::from_secs(1)) {
                if let Some(lang) = langs.first() {
                    if let Ok(product) =
                        handle.read_product_string(*lang, &desc, Duration::from_secs(1))
                    {
                        name = product;
                    }
                }
            }
        }
        let is_prime = (vid, pid) == PASSPORT;
        if is_prime {
            found_prime = true;
        }
        let label = if name.is_empty() {
            String::new()
        } else {
            format!(" {name}")
        };
        let mark = if is_prime { "  Passport Prime" } else { "" };
        eprintln!(
            "ql-usb-relay: {vid:04x}:{pid:04x}{label}{mark}  bus {} addr {}",
            device.bus_number(),
            device.address()
        );
        if !is_prime {
            continue;
        }
        for index in 0..desc.num_configurations() {
            let config = device.config_descriptor(index).map_err(io::Error::other)?;
            for descriptor in config
                .interfaces()
                .flat_map(|interface| interface.descriptors())
            {
                let class = (
                    descriptor.class_code(),
                    descriptor.sub_class_code(),
                    descriptor.protocol_code(),
                );
                let ql = class == QL_CLASS;
                if ql {
                    found_ql = true;
                }
                let bulk: Vec<_> = descriptor
                    .endpoint_descriptors()
                    .filter(|endpoint| endpoint.transfer_type() == rusb::TransferType::Bulk)
                    .map(|endpoint| format!("{:#04x}", endpoint.address()))
                    .collect();
                eprintln!(
                    "  interface {}  class {:02x}/{:02x}/{:02x}{}  endpoints {}",
                    descriptor.interface_number(),
                    class.0,
                    class.1,
                    class.2,
                    if ql { "  QL" } else { "" },
                    bulk.join(" ")
                );
            }
        }
    }
    if !found_prime {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no Passport Prime on USB",
        ));
    }
    if !found_ql {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Passport Prime has no QL interface",
        ));
    }
    Ok(())
}

fn reader_to_usb(
    handle: &DeviceHandle<GlobalContext>,
    endpoint: u8,
    max_packet: usize,
    mut reader: impl Read,
) -> io::Result<()> {
    let mut record = Vec::new();
    loop {
        let mut length = [0; 4];
        match reader.read_exact(&mut length) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > MAX_FRAMED_RECORD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "record too long",
            ));
        }
        record.resize(length, 0);
        reader.read_exact(&mut record)?;
        handle
            .write_bulk(endpoint, &record, WRITE_TIMEOUT)
            .map_err(io::Error::other)?;
        // A record filling its last packet needs a zero length one to end the transfer.
        if record.len() % max_packet == 0 {
            handle
                .write_bulk(endpoint, &[], WRITE_TIMEOUT)
                .map_err(io::Error::other)?;
        }
    }
}

fn usb_to_writer(handle: &DeviceHandle<GlobalContext>, endpoint: u8, mut writer: impl Write) {
    let mut buffer = vec![0; MAX_RECORD_LEN];
    loop {
        match handle.read_bulk(endpoint, &mut buffer, READ_TIMEOUT) {
            Ok(0) | Err(rusb::Error::Timeout) => {}
            Ok(length) => {
                let written = writer
                    .write_all(&(length as u32).to_be_bytes())
                    .and_then(|()| writer.write_all(&buffer[..length]))
                    .and_then(|()| writer.flush());
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
    let config = handle
        .device()
        .active_config_descriptor()
        .map_err(io::Error::other)?;
    for descriptor in config
        .interfaces()
        .flat_map(|interface| interface.descriptors())
    {
        if (
            descriptor.class_code(),
            descriptor.sub_class_code(),
            descriptor.protocol_code(),
        ) != QL_CLASS
        {
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
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Passport Prime has no QL interface",
    ))
}
