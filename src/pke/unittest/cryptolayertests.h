/**
 * @file cryptolayertests.h
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

#ifndef TEST_SRC_CRYPTOLAYERTESTS_H_
#define TEST_SRC_CRYPTOLAYERTESTS_H_

#include "palisade.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"
#include "encoding/signedintplaintextencoding.h"
#include "utils/parmfactory.h"

using namespace lbcrypto;

// this header contains some inline helper functions used to unit test PALISADE

/**
 * Generate Test Plaintext
 * @param cyclotomicOrder for the output vectors - used to calculate chunk size
 * @param ptm - plaintext modulus - used to calculate chunk size
 * @param plaintextShort
 * @param plaintextFull
 * @param plaintextLong
 */
inline void GenerateTestPlaintext(int cyclotomicOrder, const BigInteger& ptm,
	BytePlaintextEncoding& plaintextShort,
	BytePlaintextEncoding& plaintextFull,
	BytePlaintextEncoding& plaintextLong) {
	size_t strSize = plaintextShort.GetChunksize(cyclotomicOrder, ptm);

	auto randchar = []() -> char {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
	};

	string shortStr(strSize/2,0);
	std::generate_n(shortStr.begin(), strSize/2, randchar);
	plaintextShort = shortStr;

	string fullStr(strSize,0);
	std::generate_n(fullStr.begin(), strSize, randchar);
	plaintextFull = fullStr;

	string longStr(strSize*2,0);
	std::generate_n(longStr.begin(), strSize*2, randchar);
	plaintextLong = longStr;
}


#endif /* TEST_SRC_CRYPTOLAYERTESTS_H_ */
