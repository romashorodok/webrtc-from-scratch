run:
	uv run serve.py examples.ws:app

y4m:
	ffmpeg -f lavfi -i testsrc=duration=5:size=640x480:rate=30 -pix_fmt yuv420p -f yuv4mpegpipe output.y4m

y4mVerify:
	ffprobe -v error -count_frames -select_streams v:0 -show_entries stream=nb_read_frames -of default=nokey=1:noprint_wrappers=1 output.y4m
