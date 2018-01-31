/*
 * EncryptHelper.h
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

#ifndef BENCHMARK_SRC_ENCRYPTHELPER_H_
#define BENCHMARK_SRC_ENCRYPTHELPER_H_

#include "cryptocontexthelper.h"
#include "cryptocontextparametersets.h"
#include <string>
#include <map>
#include <vector>
using namespace std;

// include this file in benchmarks testing PKE operations across various predefined schemes

static vector<string> parms;

class MakeParms {
public:
	MakeParms() {
		for( auto p : lbcrypto::CryptoContextParameterSets )
			parms.push_back(p.first);

		if( parms.size() != 27 )
			cout << "WARNING: fix macros in EncryptHelper.h, size should be " << parms.size() << endl;
	}
};

static MakeParms makeParms;

#define BENCHMARK_PARMS(X) \
BENCHMARK(X)->ArgName(parms[0])->Arg(0); \
BENCHMARK(X)->ArgName(parms[1])->Arg(1); \
BENCHMARK(X)->ArgName(parms[2])->Arg(2); \
BENCHMARK(X)->ArgName(parms[3])->Arg(3); \
BENCHMARK(X)->ArgName(parms[4])->Arg(4); \
BENCHMARK(X)->ArgName(parms[5])->Arg(5); \
BENCHMARK(X)->ArgName(parms[6])->Arg(6); \
BENCHMARK(X)->ArgName(parms[7])->Arg(7); \
BENCHMARK(X)->ArgName(parms[8])->Arg(8); \
BENCHMARK(X)->ArgName(parms[9])->Arg(9); \
BENCHMARK(X)->ArgName(parms[10])->Arg(10); \
BENCHMARK(X)->ArgName(parms[11])->Arg(11); \
BENCHMARK(X)->ArgName(parms[12])->Arg(12); \
BENCHMARK(X)->ArgName(parms[13])->Arg(13); \
BENCHMARK(X)->ArgName(parms[14])->Arg(14); \
BENCHMARK(X)->ArgName(parms[15])->Arg(15); \
BENCHMARK(X)->ArgName(parms[16])->Arg(16); \
BENCHMARK(X)->ArgName(parms[17])->Arg(17); \
BENCHMARK(X)->ArgName(parms[18])->Arg(18); \
BENCHMARK(X)->ArgName(parms[19])->Arg(19); \
BENCHMARK(X)->ArgName(parms[20])->Arg(20); \
BENCHMARK(X)->ArgName(parms[21])->Arg(21); \
BENCHMARK(X)->ArgName(parms[22])->Arg(22); \
BENCHMARK(X)->ArgName(parms[23])->Arg(23); \
BENCHMARK(X)->ArgName(parms[24])->Arg(24); \
BENCHMARK(X)->ArgName(parms[25])->Arg(25); \
BENCHMARK(X)->ArgName(parms[26])->Arg(26);

#define BENCHMARK_PARMS_TEMPLATE(X,Y) \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[0])->Arg(0); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[1])->Arg(1); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[2])->Arg(2); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[3])->Arg(3); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[4])->Arg(4); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[5])->Arg(5); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[6])->Arg(6); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[7])->Arg(7); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[8])->Arg(8); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[9])->Arg(9); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[10])->Arg(10); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[11])->Arg(11); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[12])->Arg(12); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[13])->Arg(13); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[14])->Arg(14); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[15])->Arg(15); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[16])->Arg(16); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[17])->Arg(17); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[18])->Arg(18); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[19])->Arg(19); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[20])->Arg(20); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[21])->Arg(21); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[22])->Arg(22); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[23])->Arg(23); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[24])->Arg(24); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[25])->Arg(25); \
		BENCHMARK_TEMPLATE(X,Y)->ArgName(parms[26])->Arg(26);


#endif /* BENCHMARK_SRC_ENCRYPTHELPER_H_ */
