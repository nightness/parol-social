//! Audio codec pipeline (PNP-007 Section 5).
//!
//! Supports Opus (primary, high quality) and Codec2 (fallback, ultra-low bitrate).
//! Pure Rust implementations -- no C dependencies.

use parolnet_protocol::media::AudioCodec;

/// Audio encoder that wraps either Opus or Codec2.
pub struct AudioEncoder {
    codec: AudioCodecImpl,
    pub codec_type: AudioCodec,
}

#[allow(clippy::large_enum_variant)]
enum AudioCodecImpl {
    Opus(OpusEncoderInner),
    Codec2(Codec2EncoderInner),
}

struct OpusEncoderInner {
    encoder: opus_rs::OpusEncoder,
    frame_size: usize,
}

struct Codec2EncoderInner {
    codec: codec2::Codec2,
}

/// Audio decoder that wraps either Opus or Codec2.
pub struct AudioDecoder {
    codec: AudioDecoderImpl,
    pub codec_type: AudioCodec,
}

#[allow(clippy::large_enum_variant)]
enum AudioDecoderImpl {
    Opus(OpusDecoderInner),
    Codec2(Codec2DecoderInner),
}

struct OpusDecoderInner {
    decoder: opus_rs::OpusDecoder,
    frame_size: usize,
}

struct Codec2DecoderInner {
    codec: codec2::Codec2,
}

/// Audio frame -- 20ms of encoded audio.
#[derive(Clone, Debug)]
pub struct AudioFrame {
    pub codec: AudioCodec,
    pub sequence: u16,
    pub timestamp: u32,
    pub data: Vec<u8>,
}

/// Configuration for audio encoding.
#[derive(Clone, Debug)]
pub struct AudioConfig {
    pub codec: AudioCodec,
    pub sample_rate: u32,
    pub channels: u8,
    pub bitrate_bps: u32,
}

impl Default for AudioConfig {
    fn default() -> Self {
        Self {
            codec: AudioCodec::Opus,
            sample_rate: 16000,
            channels: 1,
            bitrate_bps: 24000,
        }
    }
}

impl AudioConfig {
    /// Config for ultra-low-bandwidth (mesh/BLE) scenarios.
    pub fn low_bandwidth() -> Self {
        Self {
            codec: AudioCodec::Codec2,
            sample_rate: 8000,
            channels: 1,
            bitrate_bps: 3200,
        }
    }
}

impl AudioEncoder {
    /// Create a new audio encoder with the given config.
    pub fn new(config: &AudioConfig) -> Result<Self, AudioError> {
        match config.codec {
            AudioCodec::Opus => {
                // opus-rs: OpusEncoder::new(sampling_rate: i32, channels: usize, application)
                let mut encoder = opus_rs::OpusEncoder::new(
                    config.sample_rate as i32,
                    config.channels as usize,
                    opus_rs::Application::Voip,
                )
                .map_err(|e| AudioError::CodecInit(format!("Opus encoder: {e}")))?;

                encoder.bitrate_bps = config.bitrate_bps as i32;

                // 20ms frame at the configured sample rate
                let frame_size = (config.sample_rate as usize * 20) / 1000;

                Ok(Self {
                    codec: AudioCodecImpl::Opus(OpusEncoderInner {
                        encoder,
                        frame_size,
                    }),
                    codec_type: AudioCodec::Opus,
                })
            }
            AudioCodec::Codec2 => {
                let codec = codec2::Codec2::new(codec2::Codec2Mode::MODE_3200);
                Ok(Self {
                    codec: AudioCodecImpl::Codec2(Codec2EncoderInner { codec }),
                    codec_type: AudioCodec::Codec2,
                })
            }
        }
    }

    /// Encode PCM audio samples into compressed bytes.
    ///
    /// For Opus: input is f32 samples in [-1.0, 1.0] range internally (i16 is
    /// converted). Input should be 20ms of audio at the configured sample rate.
    /// For 16kHz mono: 320 samples. For 8kHz mono: 160 samples.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, AudioError> {
        match &mut self.codec {
            AudioCodecImpl::Opus(enc) => {
                // opus-rs uses f32 input: convert i16 -> f32
                let f32_input: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32768.0).collect();
                let mut output = vec![0u8; 1275]; // max opus packet size
                let len = enc
                    .encoder
                    .encode(&f32_input, enc.frame_size, &mut output)
                    .map_err(|e| AudioError::EncodeFailed(e.to_string()))?;
                output.truncate(len);
                Ok(output)
            }
            AudioCodecImpl::Codec2(enc) => {
                // codec2: encode(&mut self, bits: &mut [u8], speech: &[i16])
                let bytes_per_frame = enc.codec.bits_per_frame().div_ceil(8);
                let mut output = vec![0u8; bytes_per_frame];
                enc.codec.encode(&mut output, pcm);
                Ok(output)
            }
        }
    }

    /// Get the expected number of PCM samples for one frame (20ms).
    pub fn frame_samples(&self) -> usize {
        match &self.codec {
            AudioCodecImpl::Opus(enc) => enc.frame_size,
            AudioCodecImpl::Codec2(enc) => enc.codec.samples_per_frame(),
        }
    }
}

impl AudioDecoder {
    /// Create a new audio decoder.
    pub fn new(config: &AudioConfig) -> Result<Self, AudioError> {
        match config.codec {
            AudioCodec::Opus => {
                let decoder =
                    opus_rs::OpusDecoder::new(config.sample_rate as i32, config.channels as usize)
                        .map_err(|e| AudioError::CodecInit(format!("Opus decoder: {e}")))?;

                let frame_size = (config.sample_rate as usize * 20) / 1000;

                Ok(Self {
                    codec: AudioDecoderImpl::Opus(OpusDecoderInner {
                        decoder,
                        frame_size,
                    }),
                    codec_type: AudioCodec::Opus,
                })
            }
            AudioCodec::Codec2 => {
                let codec = codec2::Codec2::new(codec2::Codec2Mode::MODE_3200);
                Ok(Self {
                    codec: AudioDecoderImpl::Codec2(Codec2DecoderInner { codec }),
                    codec_type: AudioCodec::Codec2,
                })
            }
        }
    }

    /// Decode compressed audio bytes back to PCM samples (i16).
    pub fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>, AudioError> {
        match &mut self.codec {
            AudioDecoderImpl::Opus(dec) => {
                // opus-rs decode uses f32 output
                let mut f32_output = vec![0.0f32; dec.frame_size * 2]; // extra room
                let len = dec
                    .decoder
                    .decode(data, dec.frame_size, &mut f32_output)
                    .map_err(|e| AudioError::DecodeFailed(e.to_string()))?;
                // Convert f32 -> i16
                let i16_output: Vec<i16> = f32_output[..len]
                    .iter()
                    .map(|&s| (s * 32767.0).clamp(-32768.0, 32767.0) as i16)
                    .collect();
                Ok(i16_output)
            }
            AudioDecoderImpl::Codec2(dec) => {
                let samples = dec.codec.samples_per_frame();
                let mut pcm = vec![0i16; samples];
                dec.codec.decode(&mut pcm, data);
                Ok(pcm)
            }
        }
    }
}

/// Errors from audio codec operations.
#[derive(Debug, thiserror::Error)]
pub enum AudioError {
    #[error("codec initialization failed: {0}")]
    CodecInit(String),
    #[error("encoding failed: {0}")]
    EncodeFailed(String),
    #[error("decoding failed: {0}")]
    DecodeFailed(String),
}
