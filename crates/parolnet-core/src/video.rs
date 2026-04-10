//! Video framing and fragmentation (PNP-007 Section 6).
//!
//! Video encoding/decoding is handled by the browser's WebCodecs API.
//! This module handles fragmentation of encoded video frames across
//! multiple relay cells, and reassembly on the receiving end.

use parolnet_protocol::media::VideoCodec;

/// A compressed video frame (produced by WebCodecs in browser).
#[derive(Clone, Debug)]
pub struct VideoFrame {
    pub codec: VideoCodec,
    pub width: u16,
    pub height: u16,
    pub is_keyframe: bool,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// A fragment of a video frame that fits in a relay cell.
#[derive(Clone, Debug)]
pub struct VideoFragment {
    pub frame_id: u32,
    pub fragment_index: u16,
    pub total_fragments: u16,
    pub is_keyframe: bool,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// Maximum fragment payload size (fits in relay cell after onion encryption).
pub const MAX_FRAGMENT_SIZE: usize = 440; // 457 - 17 bytes fragment header

/// Fragment a video frame into pieces that fit in relay cells.
pub fn fragment_video_frame(frame: &VideoFrame, frame_id: u32) -> Vec<VideoFragment> {
    if frame.data.is_empty() {
        return vec![VideoFragment {
            frame_id,
            fragment_index: 0,
            total_fragments: 1,
            is_keyframe: frame.is_keyframe,
            timestamp: frame.timestamp,
            data: vec![],
        }];
    }

    let chunks: Vec<&[u8]> = frame.data.chunks(MAX_FRAGMENT_SIZE).collect();
    let total = chunks.len() as u16;

    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| VideoFragment {
            frame_id,
            fragment_index: i as u16,
            total_fragments: total,
            is_keyframe: frame.is_keyframe && i == 0,
            timestamp: frame.timestamp,
            data: chunk.to_vec(),
        })
        .collect()
}

/// Reassemble a video frame from fragments.
/// Fragments must all have the same frame_id and be complete (0..total_fragments).
pub fn reassemble_video_frame(
    fragments: &mut Vec<VideoFragment>,
    codec: VideoCodec,
    width: u16,
    height: u16,
) -> Result<VideoFrame, VideoError> {
    if fragments.is_empty() {
        return Err(VideoError::MissingFragments("no fragments".into()));
    }

    // Sort by fragment index
    fragments.sort_by_key(|f| f.fragment_index);

    let total = fragments[0].total_fragments;
    let frame_id = fragments[0].frame_id;
    let is_keyframe = fragments.iter().any(|f| f.is_keyframe);
    let timestamp = fragments[0].timestamp;

    // Verify we have all fragments
    if fragments.len() as u16 != total {
        return Err(VideoError::MissingFragments(format!(
            "expected {total} fragments, got {}",
            fragments.len()
        )));
    }

    for (i, frag) in fragments.iter().enumerate() {
        if frag.fragment_index != i as u16 {
            return Err(VideoError::MissingFragments(format!(
                "missing fragment {i}, got index {}",
                frag.fragment_index
            )));
        }
        if frag.frame_id != frame_id {
            return Err(VideoError::MissingFragments("mixed frame_ids".into()));
        }
    }

    let mut data = Vec::new();
    for frag in fragments.iter() {
        data.extend_from_slice(&frag.data);
    }

    Ok(VideoFrame {
        codec,
        width,
        height,
        is_keyframe,
        timestamp,
        data,
    })
}

/// Errors from video operations.
#[derive(Debug, thiserror::Error)]
pub enum VideoError {
    #[error("missing fragments: {0}")]
    MissingFragments(String),
}
