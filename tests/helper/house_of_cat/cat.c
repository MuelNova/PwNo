#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


int backd00r(int a, int b, int c) {
    printf("%d %d %d", a, b, c);
    system("/bin/sh");
}


int main() {
    size_t *p = malloc(0x400);
    size_t libc = &puts - 0x80e50;
    printf("p: %p\n", p);
    printf("puts: %p\n", &puts);
    printf("backd00r: %p\n", &backd00r);
    read(0, p, 0x400);
    size_t *IO_list_all = libc + 0x21a680;
    *IO_list_all = (size_t)p;
    exit(0);
}

// gcc -g -o cat -D_FORTIFY_SOURCE=0 test.c