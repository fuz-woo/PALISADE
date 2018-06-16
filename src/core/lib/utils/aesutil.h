#ifndef _SRC_LIB_UTILS_AESUTIL_H
#define _SRC_LIB_UTILS_AESUTIL_H

#define KEY128 16
#define KEY192 24
#define KEY256 32
#define BLOCK_SIZE 16

#include "../math/backend.h"

namespace lbcrypto{
enum ModeOfOperation{CTR=0};
	class AESUtil{
	private:
		 unsigned int encryption_key[60];
		 unsigned int decryption_key[60];
		 unsigned int iv[4];
		 unsigned char no_rounds;

		 
		 int KeySchedule(unsigned int rk[], unsigned int rrk[], const unsigned char cipherKey[], int keyBytes);
		 int KeyExpansion(unsigned int rk[], const unsigned char cipherKey[], int keyBytes);

	public:
		AESUtil(unsigned char *pIV, unsigned char *pKey, unsigned int KeyLen);
		void EncryptBlock(const unsigned char pt[], unsigned char ct[]);
		void DecryptBlock(const unsigned char ct[], unsigned char pt[]);
		void Encrypt(unsigned char *pData, unsigned char *pCipher, unsigned int DataLen,ModeOfOperation mode);
		void Decrypt(unsigned char *pCipher, unsigned char *pData, unsigned int CipherLen,ModeOfOperation mode);
		void SplitIntegers(unsigned char* bytes, int64_t i1,int64_t i2);
		void CombineBytes(unsigned char* bytes, int64_t& i1,int64_t& i2);
	};
}
#endif
