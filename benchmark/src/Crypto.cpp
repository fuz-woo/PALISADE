/*
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
/*
Description:
	This code exercises the Proxy Re-Encryption capabilities of the NJIT Lattice crypto library.
	In this code we:
		- Generate a key pair.
		- Encrypt a string of data.
		- Decrypt the data.
		- Generate a new key pair.
		- Generate a proxy re-encryption key.
		- Re-Encrypt the encrypted data.
		- Decrypt the re-encrypted data.
	We configured parameters (namely the ring dimension and ciphertext modulus) to provide a level of security roughly equivalent to a root hermite factor of 1.007 which is generally considered secure and conservatively comparable to AES-128 in terms of computational work factor and may be closer to AES-256.

*/

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"


#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"

using namespace std;
using namespace lbcrypto;

#include "vechelper.h"
#include "ElementParmsHelper.h"
#include "EncryptHelper.h"

void BM_keygen(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(PRE);

		try {
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(cc->GetRootOfUnity(),
				cc->GetCyclotomicOrder(),
				cc->GetModulus());
		} catch( ... ) {}

		try {
			typename Poly::DggType dgg = Poly::DggType(4);			// Create the noise generator
		} catch( ... ) {}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		LPKeyPair<Poly> kp = cc->KeyGen();
	}
}

BENCHMARK_PARMS(BM_keygen)

void BM_encrypt(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	LPKeyPair<Poly> kp;
	Ciphertext<Poly> ciphertext;
	Plaintext plaintext;

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};


	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(PRE);

		try {
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(cc->GetRootOfUnity(),
				cc->GetCyclotomicOrder(),
				cc->GetModulus());
		} catch( ... ) {}

		try {
			typename Poly::DggType dgg = Poly::DggType(4);			// Create the noise generator
		} catch( ... ) {}

		size_t strSize = cc->GetRingDimension();

		if( strSize == 0 ) {
			state.SkipWithError( "Chunk size is 0" );
		}

		string shortStr(strSize,0);
		std::generate_n(shortStr.begin(), strSize, randchar);
		plaintext = cc->MakeStringPlaintext(shortStr);

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		LPKeyPair<Poly> kp = cc->KeyGen();
		state.ResumeTiming();

		ciphertext = cc->Encrypt(kp.publicKey, plaintext);
	}
}

BENCHMARK_PARMS(BM_encrypt)

void BM_decrypt(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	LPKeyPair<Poly> kp;
	Ciphertext<Poly> ciphertext;
	Plaintext plaintext;
	Plaintext plaintextNew;

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};


	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(PRE);

		try {
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(cc->GetRootOfUnity(),
				cc->GetCyclotomicOrder(),
				cc->GetModulus());
		} catch( ... ) {}

		try {
			typename Poly::DggType dgg = Poly::DggType(4);			// Create the noise generator
		} catch( ... ) {}

		size_t strSize = cc->GetRingDimension();

		if( strSize == 0 ) {
			state.SkipWithError( "Chunk size is 0" );
		}

		string shortStr(strSize,0);
		std::generate_n(shortStr.begin(), strSize, randchar);
		plaintext = cc->MakeStringPlaintext(shortStr);

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		LPKeyPair<Poly> kp = cc->KeyGen();
		ciphertext = cc->Encrypt(kp.publicKey, plaintext);
		state.ResumeTiming();

		DecryptResult result = cc->Decrypt(kp.secretKey,ciphertext,&plaintextNew);
	}
}

BENCHMARK_PARMS(BM_decrypt)

void BM_rekeygen(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	LPKeyPair<Poly> kp;

	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(PRE);
		cc->Enable(SHE);

		try {
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(cc->GetRootOfUnity(),
				cc->GetCyclotomicOrder(),
				cc->GetModulus());
		} catch( ... ) {
		}

		try {
			typename Poly::DggType dgg = Poly::DggType(4);			// Create the noise generator
		} catch( ... ) {
		}

		state.ResumeTiming();
	}

	while (state.KeepRunning()) {
		state.PauseTiming();
		LPKeyPair<Poly> kp = cc->KeyGen();
		LPKeyPair<Poly> kp2 = cc->KeyGen();
		state.ResumeTiming();

		LPEvalKey<Poly> evalKey;

		try {
			evalKey = cc->ReKeyGen(kp2.publicKey, kp.secretKey);
		} catch( std::exception& e ) {
			state.SkipWithError( e.what() );
		}
	}
}

BENCHMARK_PARMS(BM_rekeygen)

void BM_reencrypt(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	LPKeyPair<Poly> kp;
	Ciphertext<Poly> ciphertext;
	Ciphertext<Poly> reciphertext;
	Plaintext plaintext;
	Plaintext plaintextNew;

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};


	if( state.thread_index == 0 ) {
		state.PauseTiming();
		cc = CryptoContextHelper::getNewContext(parms[state.range(0)]);
		cc->Enable(ENCRYPTION);
		cc->Enable(PRE);

		try {
		ChineseRemainderTransformFTT<BigInteger,BigVector>::PreCompute(cc->GetRootOfUnity(),
				cc->GetCyclotomicOrder(),
				cc->GetModulus());
		} catch( ... ) {}

		try {
			typename Poly::DggType dgg = Poly::DggType(4);			// Create the noise generator
		} catch( ... ) {}

		size_t strSize = cc->GetRingDimension();

		if( strSize == 0 ) {
			state.SkipWithError( "Chunk size is 0" );
		}

		string shortStr(strSize,0);
		std::generate_n(shortStr.begin(), strSize, randchar);
		plaintext = cc->MakeStringPlaintext(shortStr);

		state.ResumeTiming();
	}

	LPEvalKey<Poly> evalKey;

	while (state.KeepRunning()) {
		state.PauseTiming();
		LPKeyPair<Poly> kp = cc->KeyGen();
		LPKeyPair<Poly> kp2 = cc->KeyGen();
		try {
			evalKey = cc->ReKeyGen(kp2.publicKey, kp.secretKey);
		} catch( std::exception& e ) {
			state.SkipWithError( e.what() );
			continue;
		}

		ciphertext = cc->Encrypt(kp.publicKey, plaintext);
		state.ResumeTiming();

		reciphertext = cc->ReEncrypt(evalKey,ciphertext);

	}
}

BENCHMARK_PARMS(BM_reencrypt)

BENCHMARK_MAIN()

