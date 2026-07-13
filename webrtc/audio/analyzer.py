"""
Audio Analysis Module

Provides real-time PCM audio analysis for spectrogram visualization and ML segmentation.
Includes FFT spectrum computation, audio feature extraction, and threshold-based detection.
"""

import time
import inspect
from collections import deque
from typing import Any, Dict, Optional

import numpy as np

from webrtc.logger import Component, get_logger
from webrtc.performance import ObservedComponent, worker

logger = get_logger()


# Import FilterChain locally to avoid circular imports
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .filters import FilterChain


class AudioAnalyzer(ObservedComponent):
    """
    Real-time audio analyzer for PCM frames.

    Computes FFT spectrum and extracts audio features (RMS, ZCR, spectral centroid)
    using numpy for efficient processing.
    """

    def __init__(self, sample_rate: int = 48000, fft_size: int = 1024, filter_chain=None):
        """
        Initialize audio analyzer.

        Args:
            sample_rate: Audio sample rate in Hz (default: 48000)
            fft_size: FFT window size in samples (default: 1024)
            filter_chain: Optional FilterChain for audio preprocessing
        """
        self.sample_rate = sample_rate
        self.fft_size = fft_size
        self.filter_chain = filter_chain

        # Pre-compute FFT window and frequency bins
        self.window = np.hanning(fft_size)
        self.freq_bins = np.fft.rfftfreq(fft_size, 1 / sample_rate)

        # Downsampling: 513 FFT bins → 256 for efficient WebSocket transmission
        self.target_bins = 256
        self.downsample_indices = np.linspace(
            0, len(self.freq_bins) - 1, self.target_bins, dtype=int
        )

        self.frame_count = 0

        logger.info(
            Component.OPUS,
            "AudioAnalyzer initialized",
            sample_rate=sample_rate,
            fft_size=fft_size,
            output_bins=self.target_bins,
            has_filters=filter_chain is not None,
        )

    @worker
    def _compute_spectrum(self, pcm_bytes: bytes) -> tuple[np.ndarray, Optional[dict]]:
        """
        Compute FFT spectrum from PCM bytes.

        Args:
            pcm_bytes: Raw PCM data (i16 little-endian)

        Returns:
            (spectrum, vad_features) - Normalized magnitude spectrum (0-1) and optional VAD features
        """
        # Convert i16 PCM to float32 [-1.0, 1.0]
        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0

        # Apply filters if available
        vad_features = None
        if self.filter_chain:
            samples, vad_features = self.filter_chain.process(samples)

        # Zero-pad if needed
        if len(samples) < self.fft_size:
            samples = np.pad(samples, (0, self.fft_size - len(samples)))
        elif len(samples) > self.fft_size:
            samples = samples[: self.fft_size]

        # Apply window and compute FFT
        windowed = samples * self.window
        spectrum = np.fft.rfft(windowed)
        magnitudes = np.abs(spectrum)

        # Convert to dB scale
        db = 20 * np.log10(magnitudes + 1e-10)

        # Normalize to [0, 1]
        min_db = db.min()
        max_db = db.max()
        if max_db > min_db:
            normalized = (db - min_db) / (max_db - min_db)
        else:
            normalized = np.zeros_like(db)

        # Downsample to target bins
        downsampled = normalized[self.downsample_indices]

        return downsampled, vad_features

    @worker
    def _compute_features(self, pcm_bytes: bytes) -> Dict[str, float]:
        """
        Extract audio features from PCM bytes.

        Args:
            pcm_bytes: Raw PCM data (i16 little-endian)

        Returns:
            Dictionary with RMS, ZCR, and spectral centroid
        """
        # Convert i16 PCM to float32
        samples = np.frombuffer(pcm_bytes, dtype=np.int16).astype(np.float32) / 32768.0

        # RMS (Root Mean Square) - energy measure
        rms = float(np.sqrt(np.mean(samples**2)))

        # Zero-Crossing Rate - voice activity indicator
        sign_changes = np.sum(np.diff(np.sign(samples)) != 0)
        zcr = float(sign_changes / len(samples)) if len(samples) > 0 else 0.0

        # Spectral Centroid - "brightness" of sound
        # Zero-pad for FFT
        if len(samples) < self.fft_size:
            samples_padded = np.pad(samples, (0, self.fft_size - len(samples)))
        else:
            samples_padded = samples[: self.fft_size]

        # Compute spectrum
        windowed = samples_padded * self.window
        spectrum = np.fft.rfft(windowed)
        magnitudes = np.abs(spectrum)

        # Compute centroid
        magnitude_sum = np.sum(magnitudes)
        if magnitude_sum > 1e-10:
            spectral_centroid = float(
                np.sum(self.freq_bins * magnitudes) / magnitude_sum
            )
        else:
            spectral_centroid = 0.0

        return {"rms": rms, "zcr": zcr, "spectral_centroid": spectral_centroid}

    async def analyze_frame(
        self, pcm_bytes: bytes, timestamp: int
    ) -> Dict[str, Any]:
        """
        Analyze a single PCM audio frame.

        Runs in thread pool to avoid blocking the event loop.

        Args:
            pcm_bytes: Raw PCM data (i16 little-endian)
            timestamp: RTP timestamp for this frame

        Returns:
            Dictionary with timestamp, spectrum, and features
        """
        self.frame_count += 1

        # Run CPU-intensive computation in thread pool
        spectrum_result = self._compute_spectrum(pcm_bytes)
        spectrum, vad_features = (
            await spectrum_result if inspect.isawaitable(spectrum_result) else spectrum_result
        )
        features_result = self._compute_features(pcm_bytes)
        features = (
            await features_result if inspect.isawaitable(features_result) else features_result
        )

        # Merge VAD features into main features dict
        if vad_features:
            features.update(vad_features)

        # Convert spectrum to list of [freq, magnitude] pairs for JSON serialization
        bins = [
            [float(self.freq_bins[idx]), float(spectrum[i])]
            for i, idx in enumerate(self.downsample_indices)
        ]

        if self.frame_count <= 5 or self.frame_count % 100 == 0:
            logger.debug(
                Component.OPUS,
                "Analyzed frame",
                count=self.frame_count,
                rms=features["rms"],
                zcr=features["zcr"],
                centroid=features["spectral_centroid"],
                is_voice=features.get("is_voice", None),
            )

        return {"timestamp": timestamp, "bins": bins, "features": features}


class ThresholdDetector:
    """
    ML segmentation trigger based on audio features.

    State machine: idle → detecting → triggered
    Uses RMS and ZCR thresholds with hysteresis to prevent flapping.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize threshold detector.

        Args:
            config: Configuration dictionary with thresholds
        """
        self.rms_threshold = config.get("rms_threshold", 0.1)
        self.zcr_threshold = config.get("zcr_threshold", 0.05)
        self.duration_ms = config.get("duration_ms", 500)
        self.hysteresis = config.get("hysteresis", 0.8)

        self.state = "idle"  # 'idle', 'detecting', 'triggered'
        self.buffer_start: Optional[float] = None
        self.frames_above = 0
        self.last_trigger = False

        logger.info(
            Component.OPUS,
            "ThresholdDetector initialized",
            rms_threshold=self.rms_threshold,
            zcr_threshold=self.zcr_threshold,
            duration_ms=self.duration_ms,
            hysteresis=self.hysteresis,
        )

    def update(self, features: Dict[str, float]) -> Dict[str, Any]:
        """
        Update detector with new audio features.

        Args:
            features: Dictionary with 'rms' and 'zcr' keys

        Returns:
            Dictionary with trigger status and metadata
        """
        rms = features["rms"]
        zcr = features["zcr"]

        # Check if current frame exceeds thresholds
        above_threshold = rms > self.rms_threshold and zcr > self.zcr_threshold

        if self.state == "idle" and above_threshold:
            # Start detection
            self.state = "detecting"
            self.buffer_start = time.time()
            self.frames_above = 1
            logger.debug(Component.OPUS, "Threshold detection started", rms=rms, zcr=zcr)

        elif self.state == "detecting":
            if above_threshold:
                self.frames_above += 1
                if self.buffer_start is not None:
                    elapsed_ms = (time.time() - self.buffer_start) * 1000
                else:
                    elapsed_ms = 0

                if elapsed_ms >= self.duration_ms:
                    # Trigger condition met
                    self.state = "triggered"
                    confidence = self.frames_above / (elapsed_ms / 20)
                    logger.info(
                        Component.OPUS,
                        "Threshold triggered",
                        confidence=confidence,
                        duration_ms=elapsed_ms,
                    )
                    self.last_trigger = True
                    return {
                        "triggered": True,
                        "confidence": confidence,
                        "duration_ms": elapsed_ms,
                        "buffer_ready": True,
                    }
            else:
                # Fell below threshold, check hysteresis
                if rms < self.rms_threshold * self.hysteresis:
                    self.state = "idle"
                    logger.debug(Component.OPUS, "Threshold detection cancelled")

        elif self.state == "triggered":
            # Reset after trigger
            if not above_threshold:
                self.state = "idle"
                logger.debug(Component.OPUS, "Threshold reset to idle")
                if self.last_trigger:
                    self.last_trigger = False
                    return {"triggered": False}

        # Return current trigger state
        return {"triggered": self.state == "triggered"}

    def update_config(self, config: Dict[str, Any]):
        """
        Update detector configuration at runtime.

        Args:
            config: New configuration parameters
        """
        if "rms_threshold" in config:
            self.rms_threshold = config["rms_threshold"]
        if "zcr_threshold" in config:
            self.zcr_threshold = config["zcr_threshold"]
        if "duration_ms" in config:
            self.duration_ms = config["duration_ms"]
        if "hysteresis" in config:
            self.hysteresis = config["hysteresis"]

        logger.info(
            Component.OPUS,
            "ThresholdDetector config updated",
            rms_threshold=self.rms_threshold,
            zcr_threshold=self.zcr_threshold,
            duration_ms=self.duration_ms,
            hysteresis=self.hysteresis,
        )


class SpectrumAggregator:
    """
    Aggregates high-frequency spectrum data into lower-frequency updates.

    Reduces 50 fps → 10 fps for efficient WebSocket transmission.
    Averages spectra and features across buffer.
    """

    def __init__(self, target_rate_hz: int, ws):
        """
        Initialize spectrum aggregator.

        Args:
            target_rate_hz: Target update rate in Hz (default: 10)
            ws: WebSocket connection for sending data
        """
        self.target_rate = target_rate_hz
        self.ws = ws
        self.buffer: deque = deque()
        self.last_send = time.time()
        self.send_count = 0

        logger.info(
            Component.OPUS,
            "SpectrumAggregator initialized",
            target_rate_hz=target_rate_hz,
        )

    async def add_frame(
        self,
        spectrum_data: Dict[str, Any],
        features: Dict[str, float],
        threshold_result: Dict[str, Any],
    ):
        """
        Add a frame to the aggregation buffer.

        Args:
            spectrum_data: Spectrum analysis result
            features: Audio features
            threshold_result: Threshold detection result
        """
        self.buffer.append((spectrum_data, features, threshold_result))

        # Check if it's time to flush
        elapsed = time.time() - self.last_send
        if elapsed >= 1.0 / self.target_rate:
            await self.flush()

    async def flush(self):
        """Send aggregated spectrum data via WebSocket."""
        if not self.buffer:
            return

        try:
            # Extract data from buffer
            spectra = [s for s, _, _ in self.buffer]
            features_list = [f for _, f, _ in self.buffer]
            threshold_results = [t for _, _, t in self.buffer]

            # Average features
            avg_features = {
                "rms": float(np.mean([f["rms"] for f in features_list])),
                "zcr": float(np.mean([f["zcr"] for f in features_list])),
                "spectral_centroid": float(
                    np.mean([f["spectral_centroid"] for f in features_list])
                ),
            }

            # Use most recent spectrum (could average, but latest is more responsive)
            latest_spectrum = spectra[-1]

            # Send spectrum update
            await self.ws.send_json(
                {
                    "event": "audio_spectrum",
                    "data": {
                        "timestamp": latest_spectrum["timestamp"],
                        "bins": latest_spectrum["bins"],
                        "features": avg_features,
                    },
                }
            )

            # Send threshold event if state changed
            latest_threshold = threshold_results[-1]
            if latest_threshold.get("triggered") is not None:
                # Only send if trigger state changed
                prev_triggered = (
                    threshold_results[-2].get("triggered", False)
                    if len(threshold_results) > 1
                    else False
                )
                curr_triggered = latest_threshold.get("triggered", False)

                if curr_triggered != prev_triggered:
                    await self.ws.send_json(
                        {"event": "audio_threshold", "data": latest_threshold}
                    )

            self.send_count += 1
            if self.send_count <= 5 or self.send_count % 50 == 0:
                logger.debug(
                    Component.OPUS,
                    "Sent aggregated spectrum",
                    count=self.send_count,
                    frames_aggregated=len(self.buffer),
                    rms=avg_features["rms"],
                )

        except Exception as e:
            logger.error(Component.OPUS, "Failed to send spectrum", error=str(e))

        finally:
            # Clear buffer and update timestamp
            self.buffer.clear()
            self.last_send = time.time()

    def set_rate(self, rate_hz: int):
        """
        Update target update rate.

        Args:
            rate_hz: New target rate in Hz
        """
        self.target_rate = rate_hz
        logger.info(Component.OPUS, "Aggregator rate updated", target_rate_hz=rate_hz)
