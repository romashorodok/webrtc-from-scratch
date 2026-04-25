import { useMemo, useState } from "react";

type FilterType = "highpass" | "bandpass" | "noise_gate" | "preemphasis";

type FilterConfig =
  | { type: "highpass"; cutoff_hz: number }
  | { type: "bandpass"; low_cutoff_hz: number; high_cutoff_hz: number }
  | { type: "noise_gate"; threshold_db: number; attack_ms: number; release_ms: number }
  | { type: "preemphasis"; alpha: number };

export interface CustomFilterConfig {
  filters: FilterConfig[];
  vad?: {
    energy_threshold: number;
    zcr_threshold: number;
    hangover_frames: number;
  };
}

interface FilterSettingsProps {
  onApply?: (config: CustomFilterConfig) => void;
}

function toNumber(value: string, fallback: number) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function FilterSettings({ onApply }: FilterSettingsProps) {
  const [highpassEnabled, setHighpassEnabled] = useState(true);
  const [highpassCutoff, setHighpassCutoff] = useState(80);

  const [bandpassEnabled, setBandpassEnabled] = useState(false);
  const [bandpassLow, setBandpassLow] = useState(300);
  const [bandpassHigh, setBandpassHigh] = useState(3400);

  const [noiseGateEnabled, setNoiseGateEnabled] = useState(false);
  const [noiseGateThreshold, setNoiseGateThreshold] = useState(-40);
  const [noiseGateAttack, setNoiseGateAttack] = useState(5);
  const [noiseGateRelease, setNoiseGateRelease] = useState(50);

  const [preEmphasisEnabled, setPreEmphasisEnabled] = useState(false);
  const [preEmphasisAlpha, setPreEmphasisAlpha] = useState(0.97);

  const [vadEnabled, setVadEnabled] = useState(true);
  const [vadEnergy, setVadEnergy] = useState(0.01);
  const [vadZcr, setVadZcr] = useState(0.03);
  const [vadHangover, setVadHangover] = useState(15);

  const enabledFilters = useMemo(() => {
    const filters: FilterConfig[] = [];

    if (highpassEnabled) {
      filters.push({ type: "highpass", cutoff_hz: highpassCutoff });
    }

    if (bandpassEnabled) {
      filters.push({
        type: "bandpass",
        low_cutoff_hz: bandpassLow,
        high_cutoff_hz: bandpassHigh,
      });
    }

    if (noiseGateEnabled) {
      filters.push({
        type: "noise_gate",
        threshold_db: noiseGateThreshold,
        attack_ms: noiseGateAttack,
        release_ms: noiseGateRelease,
      });
    }

    if (preEmphasisEnabled) {
      filters.push({ type: "preemphasis", alpha: preEmphasisAlpha });
    }

    return filters;
  }, [
    bandpassEnabled,
    bandpassHigh,
    bandpassLow,
    highpassCutoff,
    highpassEnabled,
    noiseGateAttack,
    noiseGateEnabled,
    noiseGateRelease,
    noiseGateThreshold,
    preEmphasisAlpha,
    preEmphasisEnabled,
  ]);

  const apply = () => {
    const config: CustomFilterConfig = {
      filters: enabledFilters,
    };

    if (vadEnabled) {
      config.vad = {
        energy_threshold: vadEnergy,
        zcr_threshold: vadZcr,
        hangover_frames: vadHangover,
      };
    }

    onApply?.(config);
  };

  return (
    <section className="filter-panel">
      <div className="filter-panel__header">
        <div>
          <p className="page-kicker">Custom audio chain</p>
          <h3>Filter Settings</h3>
        </div>
        <p className="page-copy">Build a filter chain and optional VAD settings, then send it to the server.</p>
      </div>

      <div className="filter-grid">
        <fieldset className="filter-card">
          <legend>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={highpassEnabled}
                onChange={(event) => setHighpassEnabled(event.currentTarget.checked)}
              />
              <span>High-pass</span>
            </label>
          </legend>
          <label>
            Cutoff Hz
            <input
              type="number"
              min={20}
              max={2000}
              step={1}
              value={highpassCutoff}
              onChange={(event) => setHighpassCutoff(toNumber(event.currentTarget.value, 80))}
            />
          </label>
        </fieldset>

        <fieldset className="filter-card">
          <legend>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={bandpassEnabled}
                onChange={(event) => setBandpassEnabled(event.currentTarget.checked)}
              />
              <span>Band-pass</span>
            </label>
          </legend>
          <div className="two-up">
            <label>
              Low Hz
              <input
                type="number"
                min={20}
                max={12000}
                step={1}
                value={bandpassLow}
                onChange={(event) => setBandpassLow(toNumber(event.currentTarget.value, 300))}
              />
            </label>
            <label>
              High Hz
              <input
                type="number"
                min={100}
                max={20000}
                step={1}
                value={bandpassHigh}
                onChange={(event) => setBandpassHigh(toNumber(event.currentTarget.value, 3400))}
              />
            </label>
          </div>
        </fieldset>

        <fieldset className="filter-card">
          <legend>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={noiseGateEnabled}
                onChange={(event) => setNoiseGateEnabled(event.currentTarget.checked)}
              />
              <span>Noise gate</span>
            </label>
          </legend>
          <div className="two-up">
            <label>
              Threshold dB
              <input
                type="number"
                min={-90}
                max={0}
                step={1}
                value={noiseGateThreshold}
                onChange={(event) => setNoiseGateThreshold(toNumber(event.currentTarget.value, -40))}
              />
            </label>
            <label>
              Attack ms
              <input
                type="number"
                min={1}
                max={100}
                step={1}
                value={noiseGateAttack}
                onChange={(event) => setNoiseGateAttack(toNumber(event.currentTarget.value, 5))}
              />
            </label>
          </div>
          <label>
            Release ms
            <input
              type="number"
              min={1}
              max={250}
              step={1}
              value={noiseGateRelease}
              onChange={(event) => setNoiseGateRelease(toNumber(event.currentTarget.value, 50))}
            />
          </label>
        </fieldset>

        <fieldset className="filter-card">
          <legend>
            <label className="toggle-row">
              <input
                type="checkbox"
                checked={preEmphasisEnabled}
                onChange={(event) => setPreEmphasisEnabled(event.currentTarget.checked)}
              />
              <span>Pre-emphasis</span>
            </label>
          </legend>
          <label>
            Alpha
            <input
              type="number"
              min={0}
              max={1}
              step={0.01}
              value={preEmphasisAlpha}
              onChange={(event) => setPreEmphasisAlpha(toNumber(event.currentTarget.value, 0.97))}
            />
          </label>
        </fieldset>
      </div>

      <fieldset className="filter-card filter-card--wide">
        <legend>
          <label className="toggle-row">
            <input
              type="checkbox"
              checked={vadEnabled}
              onChange={(event) => setVadEnabled(event.currentTarget.checked)}
            />
            <span>Voice activity detector</span>
          </label>
        </legend>
        <div className="two-up">
          <label>
            Energy threshold
            <input
              type="number"
              min={0}
              max={1}
              step={0.01}
              value={vadEnergy}
              onChange={(event) => setVadEnergy(toNumber(event.currentTarget.value, 0.01))}
            />
          </label>
          <label>
            ZCR threshold
            <input
              type="number"
              min={0}
              max={1}
              step={0.01}
              value={vadZcr}
              onChange={(event) => setVadZcr(toNumber(event.currentTarget.value, 0.03))}
            />
          </label>
        </div>
        <label>
          Hangover frames
          <input
            type="number"
            min={0}
            max={50}
            step={1}
            value={vadHangover}
            onChange={(event) => setVadHangover(toNumber(event.currentTarget.value, 15))}
          />
        </label>
      </fieldset>

      <div className="filter-summary">
        <div>
          <span className="status-label">Active filters</span>
          <p>{enabledFilters.length ? enabledFilters.map((filter) => filter.type).join(", ") : "none"}</p>
        </div>
        <button type="button" onClick={apply}>
          Apply Custom Filters
        </button>
      </div>
    </section>
  );
}
