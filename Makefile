all: twofish-benchmark

tables.h: makeCtables.py myref.py
	python3 makeCtables.py > tables.h

twofish-benchmark: opt2.c tables.h
	gcc -O3 -Wall -o twofish-benchmark opt2.c

clean:
	rm tables.h twofish-benchmark
