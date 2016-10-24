#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>


int main(int argc, char *argv[])
{
	void (*f)(void);
	struct stat st;
	void *p;
	int fd;

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)
		err(1, "open");

	if (fstat(fd, &st) == -1)
		err(1, "fstat");

	p = mmap(NULL, st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err(1, "mmap");

	f = (void *)p;
	f();

	close(fd);

	return 0;
}
