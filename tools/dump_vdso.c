/*
 * Dump vDSO for debugging purposes.
 */

#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/mman.h>


static unsigned long get_vdso_addr(void)
{
	char buf[4096], *p;
	bool found;
	FILE *fp;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		warn("fopen(\"/proc/self/maps\")");
		return -1;
	}

	found = false;
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, "[vdso]")) {
			found = true;
			break;
		}
	}

	fclose(fp);

	if (!found) {
		fprintf(stderr, "failed to find vdso in /proc/self/maps");
		return -1;
	}

	p = strchr(buf, '-');
	*p = '\0';

	return strtoll(buf, NULL, 16);
}

int main(int argc, char *argv[])
{
	unsigned long vdso_addr;
	int fd;

	vdso_addr = get_vdso_addr();
	printf("[*] vdso addr: %016lx\n", vdso_addr);

	fd = open(argv[1], O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (fd == -1)
		err(1, "open");

	write(fd, (void *)vdso_addr, 0x2000);

	return 0;
}
