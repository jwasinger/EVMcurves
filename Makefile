all:
	python3 genhuff.py > miller_loop.huff && \
	node compile.js > main.hex
