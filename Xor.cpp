#include "xor.h"

unsigned long __stdcall PolyXorKey(unsigned long dwKey) {
	unsigned int i = 0, j = 0, n = 0;
	unsigned char* pKey = (unsigned char*)&dwKey;
	unsigned char bVal = 0, bTmp = 0, bTmp2 = 0;
	dwKey ^= 0x5DEECE66DL + 2531011;
	for (i = 0; i < sizeof(unsigned long); i++, pKey++) {
		bVal = *pKey;
		for (j = 0x80, n = 7; j > 0x01; j /= 2, n--) {
			bTmp = (bVal & j) >> n;
			bTmp2 = (bVal & j / 2) >> (n - 1);
			bTmp ^= bTmp2;
			bTmp <<= n;
			bVal |= bTmp;
		}
		bTmp = bVal & 0x01;
		bTmp2 = bVal & 0x80 >> 7;
		bTmp ^= bTmp2;

		*pKey = bVal;
	}/* end for */
	return dwKey;
}

void __stdcall XorArray(unsigned long dwKey, unsigned char* pPoint, unsigned char* pOut, unsigned int iLength) {
	unsigned long dwNextKey = dwKey;
	unsigned char* pKey = (unsigned char*)&dwNextKey;
	unsigned int i = 0, j = 0;
	for (i = 0; i < iLength; i++) {
		pOut[i] = pPoint[i] ^ pKey[j];
		if (j == 3) {
			// ±ä»»Key
			dwNextKey = PolyXorKey(dwNextKey);
			j = 0;
		} else j++;
	}
}

void __stdcall XorArrayForArray(unsigned long dwKey, unsigned char* pPoint, unsigned char* pOut, unsigned int iLength) {
	//static unsigned long dwNextKey = 0;
	//static unsigned char* pKey = 0;
	//static unsigned int j = 0;
	//unsigned int i = 0;

	//if (dwNextKey == 0)
	//	dwNextKey = dwKey;

	//if (pKey == 0)
	//	pKey = (unsigned char*)&dwNextKey;

	//for (i = 0; i < iLength; i++) {
	//	pOut[i] = pPoint[i] ^ pKey[j];
	//	if (j == 3) {
	//		 //±ä»»Key
	//		dwNextKey = PolyXorKey(dwNextKey);
	//		j = 0;
	//	} else j++;
	//}

	unsigned char bKey = dwKey >> 24;
	unsigned int i = 0, j = 0;
	for (i = 0; i < iLength; i++) {
		pOut[i] = pPoint[i] ^ bKey;
	}
}

void __stdcall XorCoder(unsigned char* pKey, unsigned char* pBuffer, unsigned int iLength) {
	unsigned int i = 0;
	for (i = 0; i < iLength; i++)
		pBuffer[i] = pBuffer[i] ^ pKey[i];
}

void __stdcall XorKey32Bits(unsigned long dwKeyContext, unsigned char* pKey, unsigned int iKeyLength) {
	unsigned int i = 0, iCount = 0;
	unsigned long dwKey = dwKeyContext;
	unsigned char* pOutPut = pKey;
	iCount = (iKeyLength % sizeof(unsigned long) != 0) ? iKeyLength / sizeof(unsigned long) + 1 : iKeyLength / sizeof(unsigned long);

	while (iCount--) {
		dwKey = PolyXorKey(dwKey);
		*(unsigned long *)pOutPut ^= dwKey;
		pOutPut += sizeof(unsigned long);
	}
}

