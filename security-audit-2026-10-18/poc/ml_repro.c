#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
int main(void) {
    char *small = malloc(1 << 20);            /* ~1 MiB, mimics small startup RSS */
    memset(small, 1, 1 << 20);
    int rc = mlockall(MCL_CURRENT | MCL_FUTURE);
    printf("mlockall(MCL_CURRENT|MCL_FUTURE) rc=%d (errno=%d)\n", rc, errno);
    errno = 0;
    void *big = malloc(64u << 20);            /* exactly the default Argon2 buffer size */
    printf("malloc(64 MiB) -> %s (errno=%d)\n", big ? "OK" : "NULL (failed)", errno);
    if (big) { memset(big, 1, 64u << 20); printf("touch OK\n"); }
    return 0;
}
