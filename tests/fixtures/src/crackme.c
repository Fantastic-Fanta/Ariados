/* HARMLESS crackme fixture: password is "h4ck3r-5Ecr3t". */
#include <stdio.h>
#include <string.h>
static int check(const char *s) { return strcmp(s, "h4ck3r-5Ecr3t") == 0; }
int main(void) {
    char buf[64];
    printf("Enter password: ");
    if (scanf("%63s", buf) == 1) {
        if (check(buf)) puts("Correct! Access granted.");
        else puts("Wrong password. Access denied.");
    }
    return 0;
}
