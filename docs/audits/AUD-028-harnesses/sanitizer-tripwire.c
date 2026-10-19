/* AUD-028 intentional failures: never linked into MHFE or its library. */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
#if defined(MHFE_AUDIT_ASAN)
    volatile unsigned char *area = malloc(16);
    if (!area) return 3;
    unsigned char value = area[atoi(argv[1])];
    free((void *)area);
    printf("%u\n", value);
#else
    volatile int value = INT_MAX;
    printf("%d\n", value + atoi(argv[1]));
#endif
    return 0;
}
