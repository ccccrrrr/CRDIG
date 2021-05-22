start: copy.c start.c
	gcc start.c -o start

clean:
	rm -f *.o start *~