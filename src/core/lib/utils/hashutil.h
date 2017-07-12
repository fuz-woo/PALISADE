/**
 * @file hashutil.h hash utilities.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 
#ifndef _SRC_LIB_UTILS_HASHUTIL_H
#define _SRC_LIB_UTILS_HASHUTIL_H
#include "../encoding/byteplaintextencoding.h"

enum HashAlgorithm { SHA_256 = 0, SHA_512 = 1 };

class HashUtil {
public:
	static lbcrypto::BytePlaintextEncoding Hash(lbcrypto::BytePlaintextEncoding message, HashAlgorithm algo) {
		switch (algo) {
		case SHA_256:
			return SHA256(message);
		case SHA_512:
		  std::cerr <<"error SHA512 disabled, returning SHA256 instead"<<std::endl;
			return SHA256(message);
		default:
			throw std::logic_error("ERROR: Unknown Hash Algorithm");
			return lbcrypto::BytePlaintextEncoding();
		}
	}
private:
	static lbcrypto::BytePlaintextEncoding SHA256(lbcrypto::BytePlaintextEncoding message);
	static lbcrypto::BytePlaintextEncoding SHA512(lbcrypto::BytePlaintextEncoding message);
	static const uint32_t k_256[64];
	static const uint64_t k_512[80];
};

#endif
