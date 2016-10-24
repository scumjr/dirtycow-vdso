CFLAGS := -Wall

all: dump_vdso test_payload

dump_vdso: dump_vdso.o
	$(CC) -o $@ $^ $(LDFLAGS)

test_payload: test_payload.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(CFLAGS)

clean:
	rm -f *.o dump_vdso test_payload
