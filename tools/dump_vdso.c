/*
 * Dump vDSO for debugging purposes.
 */

#include <err.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/mman.h>


static unsigned long get_vdso_addr(void)
{
	return getauxval(AT_SYSINFO_EHDR);
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
