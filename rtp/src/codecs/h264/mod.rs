#[cfg(test)]
mod h264_test;

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{Error, Result};
use crate::packetizer::{Depacketizer, Payloader};

/// H264Payloader payloads H264 packets
#[derive(Default, Debug, Clone)]
pub struct H264Payloader {
    sps_nalu: Option<Bytes>,
    pps_nalu: Option<Bytes>,
}

pub const STAPA_NALU_TYPE: u8 = 24;
pub const FUA_NALU_TYPE: u8 = 28;
pub const FUB_NALU_TYPE: u8 = 29;
pub const SPS_NALU_TYPE: u8 = 7;
pub const PPS_NALU_TYPE: u8 = 8;
pub const AUD_NALU_TYPE: u8 = 9;
pub const FILLER_NALU_TYPE: u8 = 12;

pub const FUA_HEADER_SIZE: usize = 2;
pub const STAPA_HEADER_SIZE: usize = 1;
pub const STAPA_NALU_LENGTH_SIZE: usize = 2;

pub const NALU_TYPE_BITMASK: u8 = 0x1F;
pub const NALU_REF_IDC_BITMASK: u8 = 0x60;
pub const FU_START_BITMASK: u8 = 0x80;
pub const FU_END_BITMASK: u8 = 0x40;

pub const OUTPUT_STAP_AHEADER: u8 = 0x78;

pub static ANNEXB_NALUSTART_CODE: Bytes = Bytes::from_static(&[0x00, 0x00, 0x00, 0x01]);

impl H264Payloader {
    /// Find the next Annex B start code (supports both 3-byte and 4-byte).
    /// Returns (start_position, start_code_length) or (-1, -1) if not found.
    fn next_ind(nalu: &Bytes, start: usize) -> (isize, isize) {
        let mut zero_count = 0;

        for (i, &b) in nalu[start..].iter().enumerate() {
            if b == 0 {
                zero_count += 1;
            } else if b == 1 && zero_count >= 2 {
                return ((start + i - zero_count) as isize, zero_count as isize + 1);
            } else {
                zero_count = 0;
            }
        }
        (-1, -1)
    }

    fn emit(&mut self, nalu: &Bytes, mtu: usize, payloads: &mut Vec<Bytes>) {
        if nalu.is_empty() {
            return;
        }

        let nalu_type = nalu[0] & NALU_TYPE_BITMASK;
        let nalu_ref_idc = nalu[0] & NALU_REF_IDC_BITMASK;

        // Strip Access Unit Delimiters and Filler
        if nalu_type == AUD_NALU_TYPE || nalu_type == FILLER_NALU_TYPE {
            return;
        }

        // Collect SPS/PPS for aggregation — store and defer until a non-param NALU arrives
        if nalu_type == SPS_NALU_TYPE {
            self.sps_nalu.replace(nalu.clone());
            return;
        } else if nalu_type == PPS_NALU_TYPE {
            self.pps_nalu.replace(nalu.clone());
            return;
        }

        // When both parameter sets are collected, emit STAP-A before the current slice NALU
        if let (Some(sps_nalu), Some(pps_nalu)) = (&self.sps_nalu, &self.pps_nalu) {
            let sps_len = (sps_nalu.len() as u16).to_be_bytes();
            let pps_len = (pps_nalu.len() as u16).to_be_bytes();

            let mut stap_a_nalu = Vec::with_capacity(1 + 2 + sps_nalu.len() + 2 + pps_nalu.len());
            stap_a_nalu.push(OUTPUT_STAP_AHEADER);
            stap_a_nalu.extend(sps_len);
            stap_a_nalu.extend_from_slice(sps_nalu);
            stap_a_nalu.extend(pps_len);
            stap_a_nalu.extend_from_slice(pps_nalu);
            if stap_a_nalu.len() <= mtu {
                payloads.push(Bytes::from(stap_a_nalu));
            }
            self.sps_nalu.take();
            self.pps_nalu.take();
        }

        // Single NALU
        if nalu.len() <= mtu {
            payloads.push(nalu.clone());
            return;
        }

        // FU-A - generic for ALL NAL types per RFC 6184
        let max_fragment_size = mtu as isize - FUA_HEADER_SIZE as isize;

        // According to the RFC, the first octet is skipped due to redundant information
        let mut nalu_data_index: isize = 1;
        let nalu_data_length = nalu.len() as isize - nalu_data_index;
        let mut nalu_data_remaining = nalu_data_length;

        if std::cmp::min(max_fragment_size, nalu_data_remaining) <= 0 {
            return;
        }

        while nalu_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(max_fragment_size, nalu_data_remaining);
            let mut out = BytesMut::with_capacity(FUA_HEADER_SIZE + current_fragment_size as usize);

            // FU indicator: F|NRI|Type(28)
            let b0 = FUA_NALU_TYPE | nalu_ref_idc;
            out.put_u8(b0);

            // FU header: S|E|R|Type
            let is_first = nalu_data_index == 1;
            let is_last = nalu_data_remaining == current_fragment_size && !is_first;
            let fu_header = if is_first {
                0x80 | nalu_type
            } else if is_last {
                0x40 | nalu_type
            } else {
                nalu_type
            };
            out.put_u8(fu_header);

            out.put(
                &nalu[nalu_data_index as usize..(nalu_data_index + current_fragment_size) as usize],
            );
            payloads.push(out.freeze());

            nalu_data_remaining -= current_fragment_size;
            nalu_data_index += current_fragment_size;
        }
    }
}

impl Payloader for H264Payloader {
    /// Payload fragments a H264 packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut payloads = vec![];

        // Find first start code
        let (mut start, mut sc_len) = H264Payloader::next_ind(payload, 0);
        if start < 0 {
            // No start codes found, treat entire payload as single NALU
            self.emit(payload, mtu, &mut payloads);
            return Ok(payloads);
        }

        loop {
            let nalu_start = (start + sc_len) as usize;
            let (next_start, next_sc_len) = H264Payloader::next_ind(payload, nalu_start);
            if next_start < 0 {
                // Last NALU
                self.emit(&payload.slice(nalu_start..), mtu, &mut payloads);
                break;
            } else {
                self.emit(
                    &payload.slice(nalu_start..next_start as usize),
                    mtu,
                    &mut payloads,
                );
            }
            start = next_start;
            sc_len = next_sc_len;
        }

        Ok(payloads)
    }

    fn clone_to(&self) -> Box<dyn Payloader + Send + Sync> {
        Box::new(self.clone())
    }
}

/// H264Packet represents the H264 header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct H264Packet {
    pub is_avc: bool,
    fua_buffer: Option<BytesMut>,
}

impl Depacketizer for H264Packet {
    /// depacketize parses the passed byte slice and stores the result in the H264Packet this method is called upon
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.len() <= 1 {
            return Err(Error::ErrShortPacket);
        }

        // NALU Types
        // https://tools.ietf.org/html/rfc6184#section-5.4
        let b0 = packet[0];
        let nalu_type = b0 & NALU_TYPE_BITMASK;

        // The AUD NALU can be size 2 (1 byte header, 1 byte payload)
        if packet.len() <= 2 && nalu_type != AUD_NALU_TYPE {
            return Err(Error::ErrShortPacket);
        }

        let mut payload = BytesMut::new();

        match nalu_type {
            1..=23 => {
                if self.is_avc {
                    payload.put_u32(packet.len() as u32);
                } else {
                    payload.put(&*ANNEXB_NALUSTART_CODE);
                }
                payload.put(&*packet.clone());
                Ok(payload.freeze())
            }
            STAPA_NALU_TYPE => {
                let mut curr_offset = STAPA_HEADER_SIZE;
                while curr_offset < packet.len() {
                    let nalu_size =
                        ((packet[curr_offset] as usize) << 8) | packet[curr_offset + 1] as usize;
                    curr_offset += STAPA_NALU_LENGTH_SIZE;

                    if packet.len() < curr_offset + nalu_size {
                        return Err(Error::StapASizeLargerThanBuffer(
                            nalu_size,
                            packet.len() - curr_offset,
                        ));
                    }

                    if self.is_avc {
                        payload.put_u32(nalu_size as u32);
                    } else {
                        payload.put(&*ANNEXB_NALUSTART_CODE);
                    }
                    payload.put(&*packet.slice(curr_offset..curr_offset + nalu_size));
                    curr_offset += nalu_size;
                }

                Ok(payload.freeze())
            }
            FUA_NALU_TYPE => {
                if packet.len() < FUA_HEADER_SIZE {
                    return Err(Error::ErrShortPacket);
                }

                if self.fua_buffer.is_none() {
                    self.fua_buffer = Some(BytesMut::new());
                }

                if let Some(fua_buffer) = &mut self.fua_buffer {
                    fua_buffer.put(&*packet.slice(FUA_HEADER_SIZE..));
                }

                let b1 = packet[1];
                if b1 & FU_END_BITMASK != 0 {
                    let nalu_ref_idc = b0 & NALU_REF_IDC_BITMASK;
                    let fragmented_nalu_type = b1 & NALU_TYPE_BITMASK;

                    if let Some(fua_buffer) = self.fua_buffer.take() {
                        if self.is_avc {
                            payload.put_u32((fua_buffer.len() + 1) as u32);
                        } else {
                            payload.put(&*ANNEXB_NALUSTART_CODE);
                        }
                        payload.put_u8(nalu_ref_idc | fragmented_nalu_type);
                        payload.put(fua_buffer);
                    }

                    Ok(payload.freeze())
                } else {
                    Ok(Bytes::new())
                }
            }
            _ => Err(Error::NaluTypeIsNotHandled(nalu_type)),
        }
    }

    /// is_partition_head checks if this is the head of a packetized nalu stream.
    fn is_partition_head(&self, payload: &Bytes) -> bool {
        if payload.len() < 2 {
            return false;
        }

        if payload[0] & NALU_TYPE_BITMASK == FUA_NALU_TYPE
            || payload[0] & NALU_TYPE_BITMASK == FUB_NALU_TYPE
        {
            (payload[1] & FU_START_BITMASK) != 0
        } else {
            true
        }
    }

    fn is_partition_tail(&self, marker: bool, _payload: &Bytes) -> bool {
        marker
    }
}
