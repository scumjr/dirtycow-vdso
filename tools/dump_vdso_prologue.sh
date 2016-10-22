#!/bin/bash

# Dump the first instructions of vDSO entry point.

set -e

make

./dump_vdso /tmp/vdso.bin

entrypoint=$(readelf -h /tmp/vdso.bin \
	| grep 'Entry point address'\
	| cut -d ':' -f 2 \
	| tr -d ' ' \
	| sed 's/0x//')

echo "[*] entrypoint: $entrypoint"

objdump -M intel -D /tmp/vdso.bin \
		| grep -A 5 " $entrypoint:"

rm /tmp/vdso.bin
