pub mod handshake;

use byteorder::{ByteOrder};

/// OpCode is defined as an integer number between 0 and 15, inclusive
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpCode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    Reserved(u8),
}

/// Get OpCode from a u8 type
impl From<u8> for OpCode {
    fn from(op_code: u8) -> OpCode {
        match op_code {
            0 => OpCode::Continuation,
            1 => OpCode::Text,
            2 => OpCode::Binary,
            8 => OpCode::Close,
            9 => OpCode::Ping,
            10 => OpCode::Pong,
            _ => OpCode::Reserved(op_code),
        }
    }
}

/// Into a u8 type from an OpCode
impl Into<u8> for OpCode {
    fn into(self) -> u8 {
        match self {
            OpCode::Continuation => 0,
            OpCode::Text => 1,
            OpCode::Binary => 2,
            OpCode::Close => 8,
            OpCode::Ping => 9,
            OpCode::Pong => 10,
            OpCode::Reserved(i) => i,
        }
    }
}

/// Web Socket frame header
pub struct FrameHeader {
    pub is_final: bool,
    pub op_code: OpCode,
    pub mask: Option<[u8; 4]>,
    pub payload_length: usize
}

/// Web Socket frame reader
pub struct FrameReader<'a> {
    // borrow u8 slice, don't take ownership
    pub buffer: &'a [u8],
    pub is_complete: bool,

    // frame header info
    pub is_final: bool,
    pub op_code: OpCode,
    pub is_masked: bool,
    pub mask: Option<&'a [u8]>,
    pub payload_begin: usize,
    pub payload_end: usize,
}

impl<'a> FrameReader<'a> {
    /// Wrap a buffer of bytes to read the web socket frame
    pub fn wrap(buffer: &'a [u8]) -> Self {
        // get the first 16 bytes of the frame header
        let first = buffer[0];
        let second = buffer[1];
        let mut pos: usize = 2;

        let is_final = first & 0x80 != 0;
        let op_code = OpCode::from(first & 0x0F);
        let is_masked = second & 0x80 != 0;

        // reserved bits
        // let rsv1 = first & 0x40 != 0;
        // let rsv2 = first & 0x20 != 0;
        // let rsv3 = first & 0x10 != 0;

        // if the length byte is 125 or less, then that is the payload length
        // if the length is 126, read the next 16 bits and interpret those as an unsigned integer u16
        // if the length is 127, read the next 64 bits and interpret those as an unsigned integer (The most significant bit MUST be 0)

        let length_byte = second & 0x7F;
        let length_begin = pos;
        let payload_length: u64 = match length_byte {
            126 => {
                pos += 2;
                // read network endian u16
                u64::from(byteorder::NetworkEndian::read_u16(&buffer[length_begin..pos]))
            }
            127 => {
                pos += 8;
                // read network endian u64
                byteorder::NetworkEndian::read_u64(&buffer[length_begin..pos])
            }
            _ => u64::from(length_byte),
        };

        let mask = if is_masked {
            // mask length is 32 bytes (4 elements in a [u8]) so increment pos by 4
            let mask_begin = pos;
            pos += 4;
            Some(&buffer[mask_begin..pos])
        } else {
            None
        };

        // payload begin index and one-past-the-end index
        // TODO: should I use raw pointers for begin and end like I would in C++? ... probably not safe
        let payload_begin = pos;

        // payload end index is position + payload length
        let payload_end = pos + payload_length as usize;

        // the message is not complete if the payload is past the end of the buffer
        let is_complete = payload_end <= buffer.len();

        FrameReader {
            buffer,
            is_complete,
            is_final,
            op_code,
            is_masked,
            mask,
            payload_begin,
            payload_end,
        }
    }

    /// Get the payload
    pub fn payload(&self) -> &[u8] {
        self.buffer[self.payload_begin..self.payload_end].as_ref()
    }

    /// Get the length of the payload
    pub fn payload_len(&self) -> usize {
        self.payload_end - self.payload_begin
    }

    /// Get a pointer to the beginning of the payload
    pub fn payload_ptr(&self) -> *const u8 {
        unsafe {self.buffer.as_ptr().add(self.payload_begin) }
    }
}

/// Web Socket frame writer
pub struct FrameWriter<'a> {
    buffer: &'a mut [u8],
    next_pos: usize,
    mask: Option<[u8; 4]>,
}

impl<'a> FrameWriter<'a> {
    /// Wrap the buffer of bytes to
    pub fn wrap(buffer: &'a mut [u8]) -> Self {
        FrameWriter {
            buffer,
            next_pos: 0,
            mask: None
        }
    }

    /// Get the length of the frame
    pub fn frame_len(&self) -> usize {
        self.next_pos
    }

    /// Write the frame header
    pub fn push_back_header(&mut self, header: &FrameHeader) {
        let op_code: u8 = header.op_code.into();

        // bitwise OR the final flag, op code, and reserved bits for the first element
        // assume rsv1, rsv2, and rsv3 are false
        // TODO: support rsv1, rsv2, rsv3 in frame header
        let first = {
            op_code | if header.is_final { 0x80 } else { 0 } | 0 | 0 | 0
        };
        self.buffer[self.next_pos] = first;
        self.next_pos += 1;

        // determine payload length and mask flag
        let payload_length = PayloadLength::from(header.payload_length);
        let length_byte = get_byte(&payload_length);

        // bitwise OR the length byte and mask flag
        let second = { length_byte | if header.mask.is_some() { 0x80 } else { 0 } };
        self.buffer[self.next_pos] = second;
        self.next_pos += 1;

        // write the payload length extra bytes if length is u16 or u64
        match payload_length {
            PayloadLength::U16 (len, _byte) => {
                let begin = self.next_pos;
                let end = begin + 2;
                self.next_pos = end;
                byteorder::NetworkEndian::write_u16(&mut self.buffer[begin..end], len);
            },
            PayloadLength::U64 (len, _byte) => {
                let begin = self.next_pos;
                let end = begin + 8;
                self.next_pos = end;
                byteorder::NetworkEndian::write_u64(&mut self.buffer[begin..end], len);
            },
            _ => {}
        };

        // write the optional mask to the buffer
        if let Some(ref mask) = header.mask {
            let begin = self.next_pos;
            let end = self.next_pos + 4;
            self.next_pos = end;
            self.buffer[begin..end].copy_from_slice(mask);
            self.mask = header.mask.clone();
        }
    }

    /// Write the data payload
    pub fn push_back_payload(&mut self, payload: &[u8]) {
        let remaining = self.buffer.len() - self.next_pos;
        if payload.len() > remaining {
            // frame writer buffer is full
            // FIXME: error
        }
        // write the payload to the writer's buffer
        let begin = self.next_pos;
        let end = self.next_pos + payload.len();
        self.next_pos = end;
        self.buffer[begin..end].copy_from_slice(payload);

        // apply mask to the payload
        if let Some(mask) = self.mask {
            apply_mask(&mut self.buffer[begin..end], mask)
        }
    }
}

/// Generate a mask key
pub fn generate_mask() -> [u8; 4] {
    rand::random()
}

/// Apply the mask key
fn apply_mask(buf: &mut [u8], mask: [u8; 4]) {
    for (i, byte) in buf.iter_mut().enumerate() {
        *byte ^= mask[i & 3];
    }
}

/// Payload length of a web socket frame
///
/// The payload length is represented as a tuple where the first element is the actual length and
/// the second element is the byte length as defined in the protocol
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum PayloadLength {
    U8 (u8, u8),
    U16 (u16, u8),
    U64 (u64, u8)
}

/// Get the byte length
fn get_byte(payload: &PayloadLength) -> u8 {
    match payload {
        PayloadLength::U8(_l, b) => *b,
        PayloadLength::U16(_l, b) => *b,
        PayloadLength::U64(_l, b) => *b,
    }
}

/// Get PayloadLength from a length
impl From<usize> for PayloadLength {
    fn from(length: usize) -> Self {
        if length < 126 {
            PayloadLength::U8 (length as u8, length as u8)
        } else if length < 65536 {
            PayloadLength::U16 (length as u16, 126)
        } else {
            PayloadLength::U64 (length as u64, 127)
        }
    }
}


const MAX_MESSAGE_SIZE: usize = 65536;

/// Assemble a complete and valid frame
pub struct FrameAssembler {
    offset: usize,
    // TODO: use an IoVec or IoSlice?
    frame_buffer: [u8; MAX_MESSAGE_SIZE],
}

impl FrameAssembler {
    /// Allocate a new instance of a frame assembler
    pub fn new() -> Self {
        FrameAssembler {
            offset: 0,
            frame_buffer: [0 as u8; MAX_MESSAGE_SIZE],
        }
    }

    /// Read from a slice of bytes
    ///
    /// The callback function is called when a complete and valid frame is read
    pub fn read(&mut self, buffer: &[u8], handler: fn(op_code: u8, buffer: &[u8])) {
        // update internal buffer
        // TODO: avoid the memcpy from buffer to internal buffer
        let end = self.offset + buffer.len();
        self.frame_buffer[self.offset..end].copy_from_slice(buffer);

        let mut next = 0;
        while next < end {
            // wrap the buffer to try to read a frame
            let frame_reader = FrameReader::wrap(&self.frame_buffer[next..end]);

            // incomplete frame occurs when payload end is past the end of the buffer
            if !frame_reader.is_complete {
                // at least 1 complete frame was read so we need to do a memmove of the remaining
                // bytes that compose the beginning of the partial message
                if next > 0 {
                    // length to copy is beginning of the partial frame to the end of the buffer
                    let len_to_copy = end - next;

                    // memmove of [next..end] to start index offset
                    // self.frame_buffer.copy_within(next..end, next);
                    self.frame_buffer.copy_within(next..end, 0);

                    // update offset to the length copied
                    self.offset = len_to_copy;
                } else {
                    // update offset to the end of the buffer
                    self.offset = end;
                }
                // break out of the while loop
                break;
            }

            // complete frame
            // call the function callback with the op code and payload
            handler(
                frame_reader.op_code.into(),
                &frame_reader.buffer[frame_reader.payload_begin..frame_reader.payload_end],
            );

            // advance next to the start of the next frame
            next += frame_reader.payload_end;

            // reset the offset to 0 whenever a complete frame is read
            self.offset = 0;
        }
    }
}


#[cfg(test)]
mod tests {
    use crate::{OpCode, PayloadLength, get_byte, FrameHeader, FrameWriter, FrameReader, FrameAssembler};

    #[test]
    fn op_code_from_u8() {
        let codes: Vec<u8> = vec![0, 1, 2, 8, 9, 10];
        let op_codes: Vec<OpCode> = vec![OpCode::Continuation, OpCode::Text, OpCode::Binary, OpCode::Close, OpCode::Ping, OpCode::Pong];
        for i in 0..codes.len() {
            assert_eq!(op_codes[i], OpCode::from(codes[i]));
        }

        let codes: Vec<u8> = vec![3, 4, 5, 6, 7, 11, 12, 13, 14, 15];
        for code in codes.iter() {
            assert_eq!(OpCode::Reserved(*code), OpCode::from(*code));
        }
    }

    #[test]
    fn payload_length() {
        let payload_len = PayloadLength::from(125);
        match payload_len {
            PayloadLength::U8(l, b) => {
                assert_eq!(l, 125);
                assert_eq!(b, 125);
            },
            _ => {unreachable!()}
        }
        assert_eq!(get_byte(&payload_len), 125);

        let payload_len = PayloadLength::from(65535);
        match payload_len {
            PayloadLength::U16(l, b) => {
                assert_eq!(l, 65535);
                assert_eq!(b, 126);
            },
            _ => {unreachable!()}
        }
        assert_eq!(get_byte(&payload_len), 126);

        let payload_len = PayloadLength::from(65536);
        match payload_len {
            PayloadLength::U64(l, b) => {
                assert_eq!(l, 65536);
                assert_eq!(b, 127);
            },
            _ => {unreachable!()}
        }
        assert_eq!(get_byte(&payload_len), 127);
    }

    #[test]
    fn frame_write_then_read() {
        let payload_str = "hello";
        let payload_len = payload_str.as_bytes().len();
        let header = FrameHeader {
            is_final: true,
            op_code: OpCode::Text,
            mask: None,
            payload_length: payload_len
        };

        let mut buffer = [0 as u8; 1024];
        let mut frame_writer = FrameWriter::wrap(buffer.as_mut());
        frame_writer.push_back_header(&header);
        frame_writer.push_back_payload(payload_str.as_bytes());

        let frame_reader = FrameReader::wrap(buffer.as_ref());
        assert_eq!(true, frame_reader.is_complete);
        assert_eq!(true, frame_reader.is_final);
        assert_eq!(OpCode::Text, frame_reader.op_code);
        assert_eq!(None, frame_reader.mask);
        assert_eq!(false, frame_reader.is_masked);
        assert_eq!(payload_str.as_bytes(), frame_reader.payload());
    }

    #[test]
    fn read_incomplete() {
        let payload_str = "hello";
        let payload_len = payload_str.as_bytes().len();
        let header = FrameHeader {
            is_final: true,
            op_code: OpCode::Text,
            mask: None,
            payload_length: payload_len
        };

        let mut buffer = [0 as u8; 1024];
        let mut frame_writer = FrameWriter::wrap(buffer.as_mut());
        frame_writer.push_back_header(&header);
        frame_writer.push_back_payload(payload_str.as_bytes());

        // slice the buffer to smaller than it actually is to simulate reading from a buffer smaller
        // than the total payload size
        let frame_reader = FrameReader::wrap(&buffer[0..5]);
        assert_eq!(false, frame_reader.is_complete);
        assert_eq!(true, frame_reader.is_final);
        assert_eq!(OpCode::Text, frame_reader.op_code);
        assert_eq!(None, frame_reader.mask);
        assert_eq!(false, frame_reader.is_masked);
        // assert_eq!(payload_str.as_bytes(), frame_reader.payload());
    }

    #[test]
    fn assemble_complete_message() {
        let payload_str = "hello";
        let payload_len = payload_str.as_bytes().len();
        let header = FrameHeader {
            is_final: true,
            op_code: OpCode::Text,
            mask: None,
            payload_length: payload_len
        };

        let mut buffer = [0 as u8; 1024];
        let mut frame_writer = FrameWriter::wrap(&mut buffer[..]);
        frame_writer.push_back_header(&header);
        frame_writer.push_back_payload(payload_str.as_bytes());
        let frame_len = frame_writer.frame_len();

        let mut frame_assembler = FrameAssembler::new();

        fn handler(op_code: u8, buffer: &[u8]) {
            assert_eq!(OpCode::Text, OpCode::from(op_code));
            assert_eq!("hello", String::from_utf8_lossy(buffer).as_ref());
        }

        frame_assembler.read(&buffer[0..frame_len], handler);
    }

    #[test]
    fn assemble_incomplete_message() {
        let payload_str = "hello";
        let payload_len = payload_str.as_bytes().len();
        let header = FrameHeader {
            is_final: true,
            op_code: OpCode::Text,
            mask: None,
            payload_length: payload_len
        };

        let mut buffer = [0 as u8; 1024];
        let mut frame_writer = FrameWriter::wrap(&mut buffer[..]);
        frame_writer.push_back_header(&header);
        frame_writer.push_back_payload(payload_str.as_bytes());
        let frame_len = frame_writer.frame_len();

        let mut frame_assembler = FrameAssembler::new();

        fn handler(op_code: u8, buffer: &[u8]) {
            panic!("incomplete messages should never call the callback!")
        }

        frame_assembler.read(&buffer[0..(frame_len-1)], handler);
    }

    #[test]
    fn assemble_partial_message() {
        let payload_str = "hello";
        let payload_len = payload_str.as_bytes().len();
        let header = FrameHeader {
            is_final: true,
            op_code: OpCode::Text,
            mask: None,
            payload_length: payload_len
        };

        let mut buffer = [0 as u8; 1024];
        let mut frame_writer = FrameWriter::wrap(&mut buffer[..]);
        frame_writer.push_back_header(&header);
        frame_writer.push_back_payload(payload_str.as_bytes());
        let frame_len = frame_writer.frame_len();

        let mut frame_assembler = FrameAssembler::new();

        fn handler(op_code: u8, buffer: &[u8]) {
            assert_eq!(OpCode::Text, OpCode::from(op_code));
            assert_eq!("hello", String::from_utf8_lossy(buffer).as_ref());
        }

        frame_assembler.read(&buffer[0..(frame_len-2)], handler);
        frame_assembler.read(&buffer[(frame_len-2)..frame_len], handler);
    }

}
