
run:
	uv run serve.py examples.ws:app

opus:
	uv run serve.py examples.opus_ws:app --port 9001

client:
	uv run serve.py examples.client:app

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
