
.PHONY: help native-event-loop serve serve-native serve-asyncio asyncio run opus client

SERVER_APP ?= examples.ws:app
SERVER_PORT ?= 9000
SERVER_ARGS ?=
SYSTEM_PYTHON ?= .venv/bin/python

help:
	@printf '%s\n' \
		'serve          Build and require the native loop for the system environment' \
		'serve-asyncio  Start the WebRTC server with stock asyncio forced' \
		'native-event-loop  Build the native loop for the system project environment' \
		'opus           Build and require the native event loop' \
		'client         Build and require the native event loop'

serve: serve-native

native-event-loop:
	$(SYSTEM_PYTHON) -m webrtc.event_loop.build_native

serve-native: native-event-loop
	$(SYSTEM_PYTHON) serve.py $(SERVER_APP) --port $(SERVER_PORT) --require-native-event-loop $(SERVER_ARGS)

serve-asyncio:
	$(SYSTEM_PYTHON) serve.py $(SERVER_APP) --port $(SERVER_PORT) --force-asyncio-event-loop $(SERVER_ARGS)

asyncio: serve-asyncio

run: serve-native

opus: native-event-loop
	$(SYSTEM_PYTHON) serve.py examples.opus_ws:app --port 9001 --require-native-event-loop $(SERVER_ARGS)

client: native-event-loop
	$(SYSTEM_PYTHON) serve.py examples.client:app --require-native-event-loop $(SERVER_ARGS)

y4m:
	ffmpeg -f lavfi -i testsrc=duration=5:size=640x480:rate=30 -pix_fmt yuv420p -f yuv4mpegpipe output.y4m


transcode:
	ffmpeg -i test.mp4  -vf "scale=600:360,fps=30,setdar=1/1,setsar=1"  -pix_fmt yuv420p -f yuv4mpegpipe test.y4m



y4mVerify:
	ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of default=nokey=1:noprint_wrappers=1 output.y4m

av1:
	rav1e output.y4m \
		 -o output_av1.ivf \
		 -s 10 \
		 --low-latency \
		 -I 30 \
		 -i 15 \
		 -S 15 \
		 --tile-rows 1 \
		 --tile-cols 2 \
		 --quantizer 90 --min-quantizer 50 \
		 --tune Psnr \
		 --threads 4
