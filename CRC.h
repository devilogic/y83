#if !defined(__CRC_H__)
#define __CRC_H__

#define UPDC32(octet, crc)\
  (unsigned long)((crc_32_tab[(((unsigned long)(crc)) ^ ((unsigned char)(octet))) & 0xff] ^ (((unsigned long)(crc)) >> 8)))

unsigned long __stdcall crc32(unsigned char* data, unsigned int length);
unsigned long __stdcall crc32int(unsigned long *data);
bool __stdcall crc32_selftests ();
	
extern unsigned long crc_32_tab[];

#endif
