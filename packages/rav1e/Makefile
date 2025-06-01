
debug:
	./target/debug/rav1e output.y4m \
                                                 -o output.ivf \
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

run:
	./target/release/rav1e output.y4m \
                                                 -o output.ivf \
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

