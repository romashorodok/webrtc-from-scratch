
watch:
	cargo run -p builder

build:
	maturin develop --skip-install --bindings=pyo3
