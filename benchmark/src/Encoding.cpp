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

#define _USE_MATH_DEFINES
#include "benchmark/benchmark_api.h"

bool runOnlyOnce = true;

#include <iostream>
#include <fstream>
#include "palisade.h"

#include "cryptocontexthelper.h"

#include "encoding/encodings.h"
#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;

void BM_encoding_Scalar(benchmark::State& state) {
	usint	m = 1024;
	PlaintextModulus	ptm = 128;
	int64_t value = 47;
	Plaintext plaintext;
	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	while (state.KeepRunning()) {
		plaintext.reset( new ScalarEncoding(lp, ep, value) );
		plaintext->Encode();
	}
}

BENCHMARK(BM_encoding_Scalar);


void BM_encoding_Integer(benchmark::State& state) { // benchmark
	Plaintext plaintext;
	usint	m = 1024;
	PlaintextModulus	ptm = 128;
	int64_t mv = 58;

	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	while (state.KeepRunning()) {
		plaintext.reset( new IntegerEncoding(lp, ep, mv) );
		plaintext->Encode();
	}
}

BENCHMARK(BM_encoding_Integer);

void BM_encoding_CoefPacked(benchmark::State& state) {
	Plaintext plaintext;
	usint	m = 1024;
	PlaintextModulus	ptm = 128;
	PlaintextModulus half = ptm / 2;

	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	vector<int64_t> intvec;
	for( usint ii=0; ii<m/2; ii++)
		intvec.push_back( rand() % half );

	while (state.KeepRunning()) {
		plaintext.reset( new CoefPackedEncoding(lp,ep,intvec) );
		plaintext->Encode();
	}
}

BENCHMARK(BM_encoding_CoefPacked);

void BM_encoding_PackedIntPlaintext(benchmark::State& state) {
	Plaintext plaintext;
	shared_ptr<ILParams> lp;
	EncodingParams ep;

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };

	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusP(p);
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	lp.reset(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
	ep.reset(new EncodingParamsImpl(p,8));

	while (state.KeepRunning()) {
		plaintext.reset( new PackedEncoding(lp,ep,vectorOfInts1) );

		plaintext->Encode();
	}
}

BENCHMARK(BM_encoding_PackedIntPlaintext);

void BM_encoding_PackedIntPlaintext_SetParams(benchmark::State& state) {
	Plaintext plaintext;
	shared_ptr<ILParams> lp;
	EncodingParams ep;

	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusP(p);

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };

	if( state.thread_index == 0 ) {
		BigInteger modulusQ("955263939794561");
		BigInteger squareRootOfRoot("941018665059848");
		BigInteger bigmodulus("80899135611688102162227204937217");
		BigInteger bigroot("77936753846653065954043047918387");

		auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
		ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);


		lp.reset(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
		ep.reset(new EncodingParamsImpl(p,8));
	}

	while (state.KeepRunning()) {
		PackedEncoding::SetParams(m, p);
		state.PauseTiming();
		PackedEncoding::Destroy();
		state.ResumeTiming();
	}
}

BENCHMARK(BM_encoding_PackedIntPlaintext_SetParams);


void BM_Encoding_String(benchmark::State& state) { // benchmark
	CryptoContext<Poly> cc;
	Plaintext plaintext;

	usint	m = 1024;
	PlaintextModulus	ptm = 256;

	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParams>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	auto randchar = []() -> char {
		const char charset[] =
				"0123456789"
				"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[ rand() % max_index ];
	};

	string fullStr(m/2,0);
	std::generate_n(fullStr.begin(), m/2, randchar);

	while (state.KeepRunning()) {
		plaintext.reset( new StringEncoding(lp,ep,fullStr) );
		plaintext->Encode();
	}
}

BENCHMARK(BM_Encoding_String);

//execute the benchmarks
BENCHMARK_MAIN()



