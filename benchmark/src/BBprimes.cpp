// run this program and redirect the output into ElementParmsHelper.h
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

#include <utility>
#include <iostream>
#include <sstream>
#include <string>

#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "math/nbtheory.h"

using namespace std;
using namespace lbcrypto;

int main( int argc, char *argv[] ) {
	stringstream	macrocode1, macrocode2;
	stringstream	parmarray;
	int parmindex = 0;

	BigInteger mod, rootUnity;
	int shifts[] = { 30, 60, 100, }; //300, 500 };

	parmarray << "shared_ptr<ILParams> parmArray[] = {" << endl;

	for( int o=8; o<=8192; o *= 2 ) {
		for( size_t s = 0; s < sizeof(shifts)/sizeof(shifts[0]); s++ ) {
			string pname = "parm_" + std::to_string(o) + "_" + std::to_string(shifts[s]);
			mod = FirstPrime<BigInteger>(shifts[s], o);
			rootUnity = RootOfUnity<BigInteger>(o, mod);

			macrocode1 << "BENCHMARK(X)->ArgName(\"" << pname << "\")->Arg(" << parmindex << "); \\" << endl;
			macrocode2 << "BENCHMARK_TEMPLATE(X,Y)->ArgName(\"" << pname << "\")->Arg(" << parmindex << "); \\" << endl;
			parmindex++;

			parmarray << pname << "," << endl;

			cout << "shared_ptr<ILParams> " << pname << "( new ILParams(" << o 
			<< ", BigInteger(\"" << mod << "\"), BigInteger(\"" << rootUnity
			<< "\")) );" << endl;
		}
	}

	cout << endl;
	cout << parmarray.str() << "};" << endl << endl;

	cout << "#define DO_PARM_BENCHMARK(X) \\" << endl;
	cout << macrocode1.str() << endl << endl;
	
	cout << "#define DO_PARM_BENCHMARK_TEMPLATE(X,Y) \\" << endl;
	cout << macrocode2.str() << endl << endl;

	return 0;
}
