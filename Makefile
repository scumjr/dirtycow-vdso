CFLAGS := -Wall
LDFLAGS := -lpthread

all: dirtyvds0

dirtyvds0: dirtyvds0.o
	$(CC) -o $@ $^ $(LDFLAGS)

dirtyvds0.o: dirtyvds0.c payload.h
	$(CC) -o $@ -c $< $(CFLAGS)

payload.h: payload
	xxd -i $^ $@

payload: payload.s
	nasm -f bin -o $@ $^

clean:
	rm -f *.o *.h dirtyvds0
