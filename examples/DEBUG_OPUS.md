# Opus Audio Debug Guide

## What to Check

### Browser Console (Every 2 seconds)

Look for logs like:
```
=== WebRTC Stats ===
[BROWSER TX] SSRC=123456789, packets=500, bytes=50000, codec=...
[BROWSER RX] SSRC=987654321, packets=450, lost=50 (10.0%), concealed=25.5%, jitter=0.005
```

**Key Metrics:**
- `[BROWSER TX]` - How many packets the browser is SENDING to server
  - Should match server's received packet count
  - Should increment by ~50 packets/second (20ms per packet)

- `[BROWSER RX]` - How many packets the browser is RECEIVING from server
  - `lost` - Packet loss percentage (should be < 5%)
  - `concealed` - Audio interpolation % (should be < 10%)
  - If concealed > 50%, audio will be garbled/white noise

### Server Logs

#### 1. Initial Setup
```
[Opus] Sender SSRC: 162282510, PT: 111
[Opus] Receiver track SSRC: 3823036249
[Opus] SRTP monitor started
```
- Note the Receiver track SSRC - this is what we're listening for

#### 2. SRTP Monitor (Every 1 second)
```
[Opus] NEW SSRC DETECTED: 3823036249 (total SSRCs: 1)
[Opus] NEW SSRC DETECTED: 162282510 (total SSRCs: 2)
```
- Should see exactly 2 SSRCs (one for each direction)
- If > 2 SSRCs appear, browser may be sending multiple streams

#### 3. Packet Reception (First 20 packets)
```
[Opus] RX packet 0: seq=13410, ts=511440490, ssrc=3823036249, size=57, marker=1
[Opus] RX packet 1: seq=13412, ts=511442410, ssrc=3823036249, size=59, marker=1
[Opus] SEQ GAP! last=13410, current=13412, gap=1 packets
```

**What to Check:**
- **Sequence numbers** - Should increment by 1 each time
  - `seq=13410, 13411, 13412, 13413...` = GOOD ✅
  - `seq=13410, 13412, 13414, 13416...` = BAD ❌ (missing odd/even packets)

- **SEQ GAP messages** - Indicates dropped packets
  - `gap=1` consistently = Losing 50% of packets
  - `gap > 1` occasionally = Network packet loss

- **SSRC** - Should always match Receiver track SSRC
  - If SSRC changes, browser is using multiple streams

- **Timestamp delta** - Should increment by 960 (20ms * 48kHz)
  - 511440490 → 511442410 = 1920 samples (correct)

#### 4. Summary (Every 100 packets)
```
[Opus] Received 100 packets, 50 seq gaps, queue: 0
```
- If `seq gaps` count keeps growing, packets are being lost
- 50 gaps in 100 packets = 50% loss

## Expected Behavior (GOOD)

### Browser Console:
```
[BROWSER TX] SSRC=3823036249, packets=500, bytes=50000, codec=...
[BROWSER RX] SSRC=162282510, packets=490, lost=10 (2.0%), concealed=3.0%, jitter=0.005
```
- TX packets increasing steadily (~50/sec)
- RX loss < 5%
- Concealed samples < 10%

### Server Logs:
```
[Opus] RX packet 0: seq=13410, ts=511440490, ssrc=3823036249, size=57, marker=1
[Opus] RX packet 1: seq=13411, ts=511441450, ssrc=3823036249, size=59, marker=1
[Opus] RX packet 2: seq=13412, ts=511442410, ssrc=3823036249, size=60, marker=1
...
[Opus] Received 100 packets, 0 seq gaps, queue: 2
```
- Consecutive sequence numbers (no gaps)
- Timestamps incrementing by 960
- Zero or very few seq gaps

## Problem Scenarios

### Scenario 1: 50% Packet Loss (Current Issue)
**Browser:**
```
[BROWSER TX] SSRC=3823036249, packets=500, ...
```

**Server:**
```
[Opus] RX packet 0: seq=13410, ...
[Opus] SEQ GAP! last=13410, current=13412, gap=1 packets
[Opus] RX packet 1: seq=13412, ...
[Opus] SEQ GAP! last=13412, current=13414, gap=1 packets
...
[Opus] Received 100 packets, 50 seq gaps, queue: 0
```

**Diagnosis:** Browser sends 500 packets, server receives only 250 (every other packet missing)

**Possible Causes:**
1. **FEC packets on different SSRC** - Browser using separate SSRC for redundancy
2. **SRTP decryption failing** - Half the packets fail to decrypt (check for SRTP errors)
3. **Network MTU issues** - Some packets too large and dropped
4. **RED codec wrapper** - Redundancy packets being filtered out

**Fix:** Check SRTP monitor for multiple SSRCs, add logging to SRTP decrypt layer

### Scenario 2: Multiple SSRCs
**Server:**
```
[Opus] NEW SSRC DETECTED: 3823036249 (total SSRCs: 1)
[Opus] NEW SSRC DETECTED: 1234567890 (total SSRCs: 2)
[Opus] NEW SSRC DETECTED: 9876543210 (total SSRCs: 3)
```

**Diagnosis:** Browser using 3+ SSRCs (might be RED, FEC, or RTX)

**Fix:** Need to listen to ALL SSRCs, not just the one assigned to receiver track

### Scenario 3: Timestamps Wrong
**Server:**
```
[Opus] RX packet 0: seq=13410, ts=511440490, ...
[Opus] RX packet 1: seq=13411, ts=511440490, ...  # Same timestamp!
```

**Diagnosis:** Timestamps not incrementing = wrong clock rate or encoding issue

**Fix:** Check Opus packetizer clock rate (should be 48000 Hz)

## Next Steps

1. **Restart both browser and server** with new logging
2. **Open browser console** and watch for stats every 2 seconds
3. **Check server logs** for:
   - How many SSRCs are detected (should be exactly 2)
   - Sequence number gaps (should be 0 or very rare)
   - SSRC in received packets matches receiver track SSRC
4. **Compare browser TX packets with server RX packets**
   - Browser sends 500 packets
   - Server should receive ~490-500 packets (< 5% loss is acceptable)

If server receives exactly 50% of browser TX packets, we have the FEC/SSRC issue.
