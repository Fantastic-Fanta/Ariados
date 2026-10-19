#include <stdio.h>
#include <string.h>
int main(int argc,char**argv){
  // force a stack-constructed string (not a .rodata pointer)
  volatile char k[16];
  k[0]='o';k[1]='s';k[2]='a';k[3]='s';k[4]='c';k[5]='r';k[6]='i';k[7]='p';
  k[8]='t';k[9]=0;
  char url[32];
  strcpy((char*)url,"http://evil.io/x");
  if(argc>99){ puts((char*)k); puts(url);}
  return (int)k[0]+url[0];
}
