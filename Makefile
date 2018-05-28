CFLAGS=-std=c99

wsucrypt: main.o crypt.o
	gcc -o wsucrypt main.o crypt.o

main.o: main.c crypt.h
	gcc -c $(CFLAGS) main.c

crypt.o: crypt.c crypt.h
	gcc -c $(CFLAGS) crypt.c

clean:
	rm *.o
