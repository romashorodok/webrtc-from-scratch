"""
Audio Filters for Speech Enhancement and Noise Reduction

Provides real-time audio filtering for voice activity detection (VAD),
noise reduction, and speech enhancement. All filters use numpy only.
"""

import numpy as np
from typing import Optional

from webrtc.logger import Component, get_logger

logger = get_logger()


class AudioFilter:
    """Base class for audio filters"""

    def __init__(self, sample_rate: int = 48000):
        self.sample_rate = sample_rate

    def process(self, samples: np.ndarray) -> np.ndarray:
        """Process audio samples"""
        raise NotImplementedError


class HighPassFilter(AudioFilter):
    """
    High-pass filter to remove low-frequency rumble and noise.

    Removes frequencies below cutoff (default 80 Hz).
    Useful for removing AC hum, wind noise, and low-frequency rumble.
    """

    def __init__(self, sample_rate: int = 48000, cutoff_hz: float = 80):
        super().__init__(sample_rate)
        self.cutoff_hz = cutoff_hz

        # Simple first-order IIR high-pass filter
        # H(z) = (1 - z^-1) / (1 - a*z^-1)
        rc = 1.0 / (2 * np.pi * cutoff_hz)
        dt = 1.0 / sample_rate
        alpha = rc / (rc + dt)

        self.alpha = alpha
        self.prev_input = 0.0
        self.prev_output = 0.0

        logger.debug(
            Component.OPUS,
            "HighPassFilter initialized",
            cutoff_hz=cutoff_hz,
            alpha=alpha,
        )

    def process(self, samples: np.ndarray) -> np.ndarray:
        """Apply high-pass filter"""
        output = np.zeros_like(samples)

        for i in range(len(samples)):
            output[i] = self.alpha * (self.prev_output + samples[i] - self.prev_input)
            self.prev_input = samples[i]
            self.prev_output = output[i]

        return output


class BandPassFilter(AudioFilter):
    """
    Band-pass filter to isolate voice frequencies (300-3400 Hz).

    Telephone quality bandwidth - optimal for speech recognition.
    Removes both low-frequency noise and high-frequency hiss.
    """

    def __init__(
        self,
        sample_rate: int = 48000,
        low_cutoff_hz: float = 300,
        high_cutoff_hz: float = 3400,
    ):
        super().__init__(sample_rate)
        self.low_cutoff_hz = low_cutoff_hz
        self.high_cutoff_hz = high_cutoff_hz

        # Design simple band-pass filter using FFT approach
        # More efficient for real-time processing than cascaded IIR filters
        self.fft_size = 1024
        self.freq_bins = np.fft.rfftfreq(self.fft_size, 1 / sample_rate)

        # Create frequency mask (1 in passband, 0 outside)
        self.mask = np.zeros(len(self.freq_bins))
        passband = (self.freq_bins >= low_cutoff_hz) & (
            self.freq_bins <= high_cutoff_hz
        )
        self.mask[passband] = 1.0

        logger.debug(
            Component.OPUS,
            "BandPassFilter initialized",
            low_cutoff_hz=low_cutoff_hz,
            high_cutoff_hz=high_cutoff_hz,
        )

    def process(self, samples: np.ndarray) -> np.ndarray:
        """Apply band-pass filter"""
        # Pad to FFT size
        padded = np.pad(samples, (0, max(0, self.fft_size - len(samples))))[:self.fft_size]

        # FFT → apply mask → IFFT
        spectrum = np.fft.rfft(padded)
        filtered_spectrum = spectrum * self.mask
        filtered = np.fft.irfft(filtered_spectrum, n=self.fft_size)

        # Return original length
        return filtered[:len(samples)]


class NoiseGate(AudioFilter):
    """
    Noise gate - silence audio below threshold.

    Simple but effective for removing background noise during silence.
    Uses RMS-based threshold with attack/release smoothing.
    """

    def __init__(
        self,
        sample_rate: int = 48000,
        threshold_db: float = -40,
        attack_ms: float = 5,
        release_ms: float = 50,
    ):
        super().__init__(sample_rate)
        self.threshold = 10 ** (threshold_db / 20)  # Convert dB to linear

        # Attack/release smoothing coefficients
        self.attack_coeff = np.exp(-1.0 / (sample_rate * attack_ms / 1000))
        self.release_coeff = np.exp(-1.0 / (sample_rate * release_ms / 1000))

        self.envelope = 0.0

        logger.debug(
            Component.OPUS,
            "NoiseGate initialized",
            threshold_db=threshold_db,
            attack_ms=attack_ms,
            release_ms=release_ms,
        )

    def process(self, samples: np.ndarray) -> np.ndarray:
        """Apply noise gate"""
        output = np.zeros_like(samples)

        for i in range(len(samples)):
            # Compute RMS of current sample
            current_level = abs(samples[i])

            # Envelope follower with attack/release
            if current_level > self.envelope:
                # Attack
                self.envelope = (
                    self.attack_coeff * self.envelope
                    + (1 - self.attack_coeff) * current_level
                )
            else:
                # Release
                self.envelope = (
                    self.release_coeff * self.envelope
                    + (1 - self.release_coeff) * current_level
                )

            # Gate: apply gain based on threshold
            if self.envelope > self.threshold:
                gain = 1.0
            else:
                gain = 0.0

            output[i] = samples[i] * gain

        return output


class PreEmphasisFilter(AudioFilter):
    """
    Pre-emphasis filter to enhance high frequencies.

    Boosts high frequencies typically attenuated in speech.
    Improves speech intelligibility and recognition accuracy.
    """

    def __init__(self, sample_rate: int = 48000, alpha: float = 0.97):
        super().__init__(sample_rate)
        self.alpha = alpha
        self.prev_sample = 0.0

        logger.debug(Component.OPUS, "PreEmphasisFilter initialized", alpha=alpha)

    def process(self, samples: np.ndarray) -> np.ndarray:
        """Apply pre-emphasis filter: y[n] = x[n] - alpha * x[n-1]"""
        output = np.zeros_like(samples)

        for i in range(len(samples)):
            output[i] = samples[i] - self.alpha * self.prev_sample
            self.prev_sample = samples[i]

        return output


class VoiceActivityDetector:
    """
    Voice Activity Detection (VAD) using energy and zero-crossing rate.

    Detects speech vs silence/noise using multiple features:
    - Energy (RMS)
    - Zero-crossing rate (ZCR)
    - Spectral features

    More robust than simple threshold-based detection.
    """

    def __init__(
        self,
        sample_rate: int = 48000,
        energy_threshold: float = 0.05,
        zcr_threshold: float = 0.1,
        hangover_frames: int = 10,
    ):
        self.sample_rate = sample_rate
        self.energy_threshold = energy_threshold
        self.zcr_threshold = zcr_threshold
        self.hangover_frames = hangover_frames

        self.hangover_counter = 0
        self.is_voice = False

        logger.debug(
            Component.OPUS,
            "VoiceActivityDetector initialized",
            energy_threshold=energy_threshold,
            zcr_threshold=zcr_threshold,
            hangover_frames=hangover_frames,
        )

    def detect(self, samples: np.ndarray) -> tuple[bool, dict]:
        """
        Detect voice activity in audio samples.

        Returns:
            (is_voice, features) - tuple of bool and feature dict
        """
        # Compute energy (RMS)
        energy = np.sqrt(np.mean(samples**2))

        # Compute zero-crossing rate
        sign_changes = np.sum(np.diff(np.sign(samples)) != 0)
        zcr = sign_changes / len(samples) if len(samples) > 0 else 0.0

        # Voice detection logic
        # Voice typically has: high energy AND moderate ZCR
        is_speech = energy > self.energy_threshold and zcr > self.zcr_threshold

        # Debug logging (first 20 detections)
        if not hasattr(self, '_debug_count'):
            self._debug_count = 0
        if self._debug_count < 20:
            self._debug_count += 1
            logger.debug(
                Component.OPUS,
                "VAD detection",
                energy=round(energy, 4),
                energy_threshold=self.energy_threshold,
                zcr=round(zcr, 4),
                zcr_threshold=self.zcr_threshold,
                is_speech=is_speech,
            )

        if is_speech:
            # Speech detected - reset hangover counter
            self.is_voice = True
            self.hangover_counter = self.hangover_frames
        else:
            # No speech - decrement hangover counter
            if self.hangover_counter > 0:
                self.hangover_counter -= 1
                self.is_voice = True  # Still in hangover period
            else:
                self.is_voice = False

        features = {
            "energy": float(energy),
            "zcr": float(zcr),
            "is_voice": self.is_voice,
            "hangover_remaining": self.hangover_counter,
        }

        return self.is_voice, features


class FilterChain:
    """
    Chain of audio filters applied in sequence.

    Allows combining multiple filters for comprehensive noise reduction
    and speech enhancement.
    """

    def __init__(self, sample_rate: int = 48000):
        self.sample_rate = sample_rate
        self.filters: list[AudioFilter] = []
        self.vad: Optional[VoiceActivityDetector] = None
        self.enabled = True

        logger.info(Component.OPUS, "FilterChain initialized", sample_rate=sample_rate)

    def add_filter(self, filter: AudioFilter):
        """Add a filter to the chain"""
        self.filters.append(filter)
        logger.debug(
            Component.OPUS,
            "Filter added to chain",
            filter_type=type(filter).__name__,
            total_filters=len(self.filters),
        )

    def set_vad(self, vad: VoiceActivityDetector):
        """Set voice activity detector"""
        self.vad = vad
        logger.debug(Component.OPUS, "VAD added to filter chain")

    def clear(self):
        """Remove all filters"""
        self.filters.clear()
        self.vad = None
        logger.debug(Component.OPUS, "Filter chain cleared")

    def process(self, samples: np.ndarray) -> tuple[np.ndarray, Optional[dict]]:
        """
        Process audio through filter chain.

        Returns:
            (filtered_samples, vad_features) - tuple of filtered audio and VAD info
        """
        if not self.enabled:
            return samples, None

        # Apply filters in sequence
        filtered = samples.copy()
        for filter in self.filters:
            filtered = filter.process(filtered)

        # Apply VAD if present
        vad_features = None
        if self.vad:
            is_voice, vad_features = self.vad.detect(filtered)

            # If VAD says no voice, silence the output
            if not is_voice:
                filtered = np.zeros_like(filtered)

        return filtered, vad_features

    def set_enabled(self, enabled: bool):
        """Enable/disable entire filter chain"""
        self.enabled = enabled
        logger.info(Component.OPUS, "Filter chain enabled" if enabled else "Filter chain disabled")


# Preset filter configurations
FILTER_PRESETS = {
    "none": {
        "name": "No Filtering",
        "description": "Raw audio, no processing",
        "filters": [],
    },
    "highpass": {
        "name": "High-Pass (80 Hz)",
        "description": "Remove low-frequency rumble",
        "filters": [{"type": "highpass", "cutoff_hz": 80}],
    },
    "telephone": {
        "name": "Telephone Quality",
        "description": "Band-pass 300-3400 Hz (speech frequencies)",
        "filters": [{"type": "bandpass", "low_cutoff_hz": 300, "high_cutoff_hz": 3400}],
    },
    "wideband": {
        "name": "Wideband Speech",
        "description": "Band-pass 50-8000 Hz (wideband speech)",
        "filters": [{"type": "bandpass", "low_cutoff_hz": 50, "high_cutoff_hz": 8000}],
    },
    "noise_gate": {
        "name": "Noise Gate",
        "description": "Silence below -40 dB",
        "filters": [{"type": "noise_gate", "threshold_db": -40}],
    },
    "speech_enhancement": {
        "name": "Speech Enhancement",
        "description": "High-pass + Pre-emphasis + Noise gate",
        "filters": [
            {"type": "highpass", "cutoff_hz": 80},
            {"type": "preemphasis", "alpha": 0.95},  # Less aggressive pre-emphasis
            {"type": "noise_gate", "threshold_db": -50},  # More sensitive gate
        ],
    },
    "vad": {
        "name": "Voice Activity Detection",
        "description": "Detect and isolate speech, silence non-speech",
        "filters": [{"type": "highpass", "cutoff_hz": 80}],
        "vad": {"energy_threshold": 0.01, "zcr_threshold": 0.03, "hangover_frames": 15},  # Lower thresholds, longer hangover
    },
    "aggressive": {
        "name": "Aggressive Noise Reduction",
        "description": "Telephone band + Noise gate + VAD",
        "filters": [
            {"type": "bandpass", "low_cutoff_hz": 300, "high_cutoff_hz": 3400},
            {"type": "noise_gate", "threshold_db": -45},  # Less aggressive gate
        ],
        "vad": {"energy_threshold": 0.02, "zcr_threshold": 0.04, "hangover_frames": 12},  # Lower thresholds
    },
    "vad_debug": {
        "name": "VAD Debug (Very Sensitive)",
        "description": "Test VAD with very low thresholds - check console logs",
        "filters": [{"type": "highpass", "cutoff_hz": 80}],
        "vad": {"energy_threshold": 0.005, "zcr_threshold": 0.01, "hangover_frames": 20},  # Very low for testing
    },
}


def create_filter_chain(preset: str, sample_rate: int = 48000) -> FilterChain:
    """
    Create a filter chain from a preset configuration.

    Args:
        preset: Preset name (e.g., "telephone", "vad", "aggressive")
        sample_rate: Audio sample rate in Hz

    Returns:
        Configured FilterChain instance
    """
    if preset not in FILTER_PRESETS:
        logger.info(
            Component.OPUS, "Unknown filter preset, using 'none'", preset=preset
        )
        preset = "none"

    config = FILTER_PRESETS[preset]
    chain = FilterChain(sample_rate)

    # Add filters
    for filter_config in config.get("filters", []):
        filter_type = filter_config["type"]

        if filter_type == "highpass":
            filter = HighPassFilter(
                sample_rate, cutoff_hz=filter_config.get("cutoff_hz", 80)
            )
        elif filter_type == "bandpass":
            filter = BandPassFilter(
                sample_rate,
                low_cutoff_hz=filter_config.get("low_cutoff_hz", 300),
                high_cutoff_hz=filter_config.get("high_cutoff_hz", 3400),
            )
        elif filter_type == "noise_gate":
            filter = NoiseGate(
                sample_rate, threshold_db=filter_config.get("threshold_db", -40)
            )
        elif filter_type == "preemphasis":
            filter = PreEmphasisFilter(
                sample_rate, alpha=filter_config.get("alpha", 0.97)
            )
        else:
            logger.info(Component.OPUS, "Unknown filter type", filter_type=filter_type)
            continue

        chain.add_filter(filter)

    # Add VAD if configured
    if vad_config := config.get("vad"):
        vad = VoiceActivityDetector(
            sample_rate,
            energy_threshold=vad_config.get("energy_threshold", 0.05),
            zcr_threshold=vad_config.get("zcr_threshold", 0.1),
            hangover_frames=vad_config.get("hangover_frames", 10),
        )
        chain.set_vad(vad)

    logger.info(
        Component.OPUS,
        "Filter chain created",
        preset=preset,
        num_filters=len(chain.filters),
        has_vad=chain.vad is not None,
    )

    return chain
