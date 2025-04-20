
sync:
	@uv sync --all-extras --dev --all-packages

build:
	@uv build --all

watch:
	cargo run -p builder

gen:
	ffmpeg -f lavfi -i testsrc=duration=5:size=640x480:rate=30 -pix_fmt yuv420p -f yuv4mpegpipe output.y4m
