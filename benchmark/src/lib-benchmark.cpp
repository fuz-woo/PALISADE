/*
 * @file lib-benchmark : library benchmark routines for comparison by build
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
 * This file benchmarks a small number of operations in order to exercise large pieces of the library
 */

#define PROFILE
#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"

#include <iostream>
#include <fstream>
#include <limits>
#include <iterator>
#include <random>

#include "palisade.h"

#include "cryptocontexthelper.h"

#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

CryptoContext<DCRTPoly>
GenerateContext() {
	usint ptm = 2;
	double sigma = 3.19;
	double rootHermiteFactor = 1.0048;

	size_t count = 100;

	//Set Crypto Parameters
	CryptoContext<DCRTPoly> cryptoContext = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			ptm, rootHermiteFactor, sigma, 0, 5, 0, OPTIMIZED,3,30,55);

	// enable features that you wish to use
	cryptoContext->Enable(ENCRYPTION);
	cryptoContext->Enable(SHE);

//	std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
//	std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
//	std::cout << "log2 q = " << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;

	return cryptoContext;
}

void KeyGen(benchmark::State& state) {

	CryptoContext<DCRTPoly> cryptoContext = GenerateContext();

	LPKeyPair<DCRTPoly> keyPair;

	while (state.KeepRunning()) {
		keyPair = cryptoContext->KeyGen();
	}
}

BENCHMARK(KeyGen)->Unit(benchmark::kMicrosecond);

void Encryption(benchmark::State& state) {

	CryptoContext<DCRTPoly> cryptoContext = GenerateContext();

	LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

	std::vector<int64_t> vectorOfInts1 = {1,0,1,0,1,1,1,0,1,1,1,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	while (state.KeepRunning()) {
		auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	}
}

BENCHMARK(Encryption)->Unit(benchmark::kMicrosecond);

void MultNoRelin(benchmark::State& state) {

	CryptoContext<DCRTPoly> cryptoContext = GenerateContext();

	LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

	std::vector<int64_t> vectorOfInts1 = {1,0,1,0,1,1,1,0,1,1,1,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = {1,1,1,1,1,1,1,0,1,1,1,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	while (state.KeepRunning()) {
		auto ciphertextMul = cryptoContext->EvalMultNoRelin(ciphertext1,ciphertext2);
	}
}

BENCHMARK(MultNoRelin)->Unit(benchmark::kMicrosecond);

void MultRelin(benchmark::State& state) {

	CryptoContext<DCRTPoly> cryptoContext = GenerateContext();

	LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();
	cryptoContext->EvalMultKeyGen(keyPair.secretKey);

	std::vector<int64_t> vectorOfInts1 = {1,0,1,0,1,1,1,0,1,1,1,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	std::vector<int64_t> vectorOfInts2 = {1,1,1,1,1,1,1,0,1,1,1,0};
	Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

	while (state.KeepRunning()) {
		auto ciphertextMul = cryptoContext->EvalMult(ciphertext1,ciphertext2);
	}
}

BENCHMARK(MultRelin)->Unit(benchmark::kMicrosecond);

void Decryption(benchmark::State& state) {

	CryptoContext<DCRTPoly> cryptoContext = GenerateContext();

	LPKeyPair<DCRTPoly> keyPair = cryptoContext->KeyGen();

	std::vector<int64_t> vectorOfInts1 = {1,0,1,0,1,1,1,0,1,1,1,0};
	Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

	auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
	Plaintext plaintextDec1;

	while (state.KeepRunning()) {
		cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);
	}
}

BENCHMARK(Decryption)->Unit(benchmark::kMicrosecond);

void NTTTransform(benchmark::State& state) {

	usint m = 2048;
	usint phim = 1024;

	NativeInteger modulusQ("288230376151748609");
	NativeInteger rootOfUnity("64073710037604316");

	uint64_t nRep;

	DiscreteUniformGeneratorImpl<NativeVector> dug;
	dug.SetModulus(modulusQ);
	NativeVector x = dug.GenerateVector(phim);

	NativeVector rootOfUnityTable(phim, modulusQ);
	NativeInteger t(1);
	for (usint i = 0; i<phim; i++) {
		rootOfUnityTable.at(i)= t;
		t = t.ModMul(rootOfUnity, modulusQ);
	}

	// test runs to force all precomputations
	NativeVector X(m/2), xx(m/2);
	ChineseRemainderTransformFTT<NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	ChineseRemainderTransformFTT<NativeVector>::InverseTransform(X, rootOfUnity, m, &xx);


	while (state.KeepRunning()) {
		ChineseRemainderTransformFTT<NativeVector>::ForwardTransform(x, rootOfUnity, m, &X);
	}
}

BENCHMARK(NTTTransform)->Unit(benchmark::kMicrosecond);

BENCHMARK_MAIN()
