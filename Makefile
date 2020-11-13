all:
	rm -f main.hex miller_loop.hex miller_loop.huff
	python3 genhuff.py > miller_loop.huff
	node compile.js > main.hex
