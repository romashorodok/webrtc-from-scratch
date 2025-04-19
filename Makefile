
build:
	uv run maturin develop --skip-install --uv

watch:
	cargo run -p builder

# build:
# 	maturin develop --skip-install --bindings=pyo3

gen:
	ffmpeg -f lavfi -i testsrc=duration=5:size=640x480:rate=30 -pix_fmt yuv420p -f yuv4mpegpipe output.y4m
