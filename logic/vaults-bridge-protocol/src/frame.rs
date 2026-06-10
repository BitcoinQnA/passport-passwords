// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Line framing for newline-delimited JSON over a byte stream.
//!
//! Each request and response is a serialised JSON object terminated by a
//! single `\n`. The framing layer accumulates incoming bytes (from a
//! stream of 64-byte USB interrupt-endpoint reads on hardware, or one
//! WebSocket text frame per message in the simulator) and yields whole
//! lines.
//!
//! Aligns with `nostr-signer/browser-extension-1.3/webusb-transport.js`
//! so Prime's `os/usbdev` facility is exercised the same way by both
//! apps.

use thiserror::Error;

/// Cap on a single line to bound memory under malicious input. 16 KiB is
/// far above anything Vaults Bridge messages need.
pub const MAX_LINE_BYTES: usize = 16 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("line exceeds max size of {MAX_LINE_BYTES} bytes")]
    LineTooLong,
}

/// Wrap a JSON payload as a newline-terminated frame.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 1);
    out.extend_from_slice(payload);
    out.push(b'\n');
    out
}

#[derive(Default)]
pub struct LineSplitter {
    buf: Vec<u8>,
}

impl LineSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a byte slice. Returns 0+ complete lines and keeps any tail
    /// in the internal buffer.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, FrameError> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                let line = std::mem::take(&mut self.buf);
                out.push(line);
            } else {
                if self.buf.len() >= MAX_LINE_BYTES {
                    self.buf.clear();
                    return Err(FrameError::LineTooLong);
                }
                self.buf.push(b);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_appends_newline() {
        assert_eq!(frame(b"hello"), b"hello\n".to_vec());
    }

    #[test]
    fn split_single_line_at_once() {
        let mut s = LineSplitter::new();
        let lines = s.push(b"one\n").unwrap();
        assert_eq!(lines, vec![b"one".to_vec()]);
    }

    #[test]
    fn split_multiple_lines_in_one_chunk() {
        let mut s = LineSplitter::new();
        let lines = s.push(b"a\nbb\nccc\n").unwrap();
        assert_eq!(lines, vec![b"a".to_vec(), b"bb".to_vec(), b"ccc".to_vec()]);
    }

    #[test]
    fn split_across_chunks() {
        let mut s = LineSplitter::new();
        assert!(s.push(b"hel").unwrap().is_empty());
        assert!(s.push(b"lo, w").unwrap().is_empty());
        let lines = s.push(b"orld\n").unwrap();
        assert_eq!(lines, vec![b"hello, world".to_vec()]);
    }

    #[test]
    fn split_keeps_tail_after_last_newline() {
        let mut s = LineSplitter::new();
        let lines = s.push(b"first\nsec").unwrap();
        assert_eq!(lines, vec![b"first".to_vec()]);
        let lines = s.push(b"ond\n").unwrap();
        assert_eq!(lines, vec![b"second".to_vec()]);
    }

    #[test]
    fn rejects_oversized_line() {
        let mut s = LineSplitter::new();
        let big = vec![b'x'; MAX_LINE_BYTES + 10];
        assert_eq!(s.push(&big).unwrap_err(), FrameError::LineTooLong);
    }
}
