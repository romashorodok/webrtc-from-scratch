import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
} from "react";

export interface AudioSpectrumPayload {
  timestamp: number;
  bins: Array<[number, number]>;
  features: {
    rms: number;
    zcr: number;
    spectral_centroid: number;
    is_voice?: boolean;
    [key: string]: unknown;
  };
}

export interface AudioSpectrogramHandle {
  update: (data: AudioSpectrumPayload) => void;
  clear: () => void;
}

interface AudioSpectrogramProps {
  threshold?: number;
  height?: number;
  width?: number;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(max, Math.max(min, value));
}

function sampleSpectrum(values: number[], rows: number) {
  if (rows <= 0) {
    return [];
  }

  if (values.length <= rows) {
    return values.slice();
  }

  const out = new Array<number>(rows);
  for (let row = 0; row < rows; row += 1) {
    const start = Math.floor((row / rows) * values.length);
    const end = Math.max(start + 1, Math.floor(((row + 1) / rows) * values.length));
    let sum = 0;
    for (let index = start; index < end; index += 1) {
      sum += values[index] ?? 0;
    }
    out[row] = sum / (end - start);
  }
  return out;
}

export const AudioSpectrogram = forwardRef<AudioSpectrogramHandle, AudioSpectrogramProps>(
  function AudioSpectrogram({ threshold = 0.6, height = 300, width = 700 }, ref) {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const historyRef = useRef<number[][]>([]);
    const [latestFeatures, setLatestFeatures] = useState<AudioSpectrumPayload["features"] | null>(null);
    const [latestTimestamp, setLatestTimestamp] = useState<number | null>(null);
    const [latestBins, setLatestBins] = useState<number>(0);

    const maxColumns = useMemo(() => {
      return Math.max(48, Math.floor(width / 4));
    }, [width]);

    const draw = () => {
      const canvas = canvasRef.current;
      if (!canvas) {
        return;
      }

      const ctx = canvas.getContext("2d");
      if (!ctx) {
        return;
      }

      const ratio = window.devicePixelRatio || 1;
      const pixelWidth = Math.floor(width * ratio);
      const pixelHeight = Math.floor(height * ratio);

      if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
        canvas.width = pixelWidth;
        canvas.height = pixelHeight;
      }

      const rows = 96;
      const columns = historyRef.current;
      const columnWidth = width / Math.max(1, columns.length);
      const rowHeight = height / rows;

      ctx.save();
      ctx.scale(ratio, ratio);
      ctx.clearRect(0, 0, width, height);

      const background = ctx.createLinearGradient(0, 0, 0, height);
      background.addColorStop(0, "#07111d");
      background.addColorStop(1, "#03070d");
      ctx.fillStyle = background;
      ctx.fillRect(0, 0, width, height);

      const gridRows = 6;
      ctx.strokeStyle = "rgba(169, 207, 255, 0.08)";
      ctx.lineWidth = 1;
      for (let row = 1; row < gridRows; row += 1) {
        const y = (height / gridRows) * row;
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      columns.forEach((spectrum, columnIndex) => {
        const normalized = sampleSpectrum(spectrum, rows);
        const x = columnIndex * columnWidth;

        normalized.forEach((value, rowIndex) => {
          const intensity = clamp(value, 0, 1);
          const hue = 200 - intensity * 150;
          const alpha = 0.08 + intensity * 0.9;
          ctx.fillStyle = `hsla(${hue}, 100%, ${35 + intensity * 30}%, ${alpha})`;
          const y = height - (rowIndex + 1) * rowHeight;
          ctx.fillRect(x, y, columnWidth + 1, rowHeight + 1);
        });
      });

      if (latestFeatures) {
        const rmsBar = clamp(latestFeatures.rms * 4, 0, 1);
        ctx.fillStyle = "rgba(255, 255, 255, 0.08)";
        ctx.fillRect(0, 0, width, 5);
        ctx.fillStyle = rmsBar > threshold ? "rgba(74, 222, 128, 0.9)" : "rgba(255, 198, 92, 0.9)";
        ctx.fillRect(0, 0, width * rmsBar, 5);
      }

      ctx.restore();
    };

    useEffect(() => {
      draw();
    }, [height, latestFeatures, latestTimestamp, latestBins, maxColumns, threshold, width]);

    useImperativeHandle(ref, () => ({
      update(data: AudioSpectrumPayload) {
        const magnitudes = data.bins.map(([, magnitude]) => clamp(magnitude, 0, 1));
        historyRef.current.push(magnitudes);
        if (historyRef.current.length > maxColumns) {
          historyRef.current.splice(0, historyRef.current.length - maxColumns);
        }

        setLatestFeatures(data.features);
        setLatestTimestamp(data.timestamp);
        setLatestBins(data.bins.length);
        draw();
      },
      clear() {
        historyRef.current = [];
        setLatestFeatures(null);
        setLatestTimestamp(null);
        setLatestBins(0);
        draw();
      },
    }));

    return (
      <div className="spectrogram">
        <div className="spectrogram__frame">
          <canvas ref={canvasRef} className="spectrogram__canvas" width={width} height={height} />
        </div>

        <div className="spectrogram__legend">
          <span>Low frequency</span>
          <span>High frequency</span>
        </div>

        <div className="spectrogram__metrics">
          <span>Threshold: {threshold.toFixed(2)}</span>
          <span>Bins: {latestBins}</span>
          <span>
            Voice: {latestFeatures?.is_voice ? "active" : "idle"}
          </span>
          <span>
            RMS: {latestFeatures ? latestFeatures.rms.toFixed(3) : "0.000"}
          </span>
          <span>
            Centroid: {latestFeatures ? `${latestFeatures.spectral_centroid.toFixed(0)} Hz` : "0 Hz"}
          </span>
          <span>
            Updated: {latestTimestamp ? new Date(latestTimestamp).toLocaleTimeString() : "waiting"}
          </span>
        </div>
      </div>
    );
  },
);
