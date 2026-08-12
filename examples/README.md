## Run
```bash
make serve
```

`make serve` requires a compatible compiled native event loop and fails rather
than silently starting with stock asyncio. Use `make serve-asyncio` to force
stock asyncio even when a native artifact is installed. Additional server
arguments can be supplied with `SERVER_ARGS`, for example
`make serve-asyncio SERVER_ARGS='--packet-workers 0'`.
