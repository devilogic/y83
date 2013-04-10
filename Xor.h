#if !defined(__XOR_H__)
#define __XOR_H__

unsigned long __stdcall PolyXorKey(unsigned long dwKey);
void __stdcall XorArray(unsigned long dwKey, unsigned char* pPoint, unsigned char* pOut, unsigned int iLength);
void __stdcall XorArrayForArray(unsigned long dwKey, unsigned char* pPoint, unsigned char* pOut, unsigned int iLength);
void __stdcall XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned int iLength);
void __stdcall XorKey32Bits(unsigned long dwKeyContext, unsigned char* pKey, unsigned int iKeyLength);

#endif