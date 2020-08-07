use byteorder::{ByteOrder};

// OpCode is defined as an integer number between 0 and 15, inclusive
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

pub struct FrameHeader {
    is_final: bool,
    op_code: OpCode,
    mask: Option<[u8; 4]>,
    payload_length: usize
}

// websocket frame reader
pub struct FrameReader<'a> {
    // borrow u8 slice, don't take ownership
    buffer: &'a [u8],
    is_complete: bool,

    // frame header info
    is_final: bool,
    op_code: OpCode,
    is_masked: bool,
    mask: Option<&'a [u8]>,
    payload_begin: usize,
    payload_end: usize,
}

impl<'a> FrameReader<'a> {
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
        // TODO: does it make sense to use raw pointers for begin and end like I would in C++?
        //  ... probably not safe
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

    pub fn payload(&self) -> &[u8] {
        self.buffer[self.payload_begin..self.payload_end].as_ref()
    }

    pub fn payload_len(&self) -> usize {
        self.payload_end - self.payload_begin
    }

    pub fn payload_ptr(&self) -> *const u8 {
        unsafe {self.buffer.as_ptr().add(self.payload_begin) }
    }
}

pub struct FrameWriter<'a> {
    buffer: &'a mut [u8],
    next_pos: usize,
}

impl<'a> FrameWriter<'a> {
    pub fn wrap(buffer: &'a mut [u8]) -> Self {
        FrameWriter {
            buffer,
            next_pos: 0,
        }
    }

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
        }
    }

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
    }
}

pub struct RangeError;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum PayloadLength {
    U8 (u8, u8),
    U16 (u16, u8),
    U64 (u64, u8)
}

fn get_byte(payload: &PayloadLength) -> u8 {
    match payload {
        PayloadLength::U8(_l, b) => *b,
        PayloadLength::U16(_l, b) => *b,
        PayloadLength::U64(_l, b) => *b,
    }
}

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

#[cfg(test)]
mod tests {
    use crate::{OpCode, PayloadLength, get_byte, FrameHeader, FrameWriter, FrameReader};

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
}
