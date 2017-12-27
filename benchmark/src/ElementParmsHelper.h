/**
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

#include "lattice/elemparamfactory.h"

shared_ptr<ILParams> parm_16 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M16);
shared_ptr<ILParams> parm_1024 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M1024);
shared_ptr<ILParams> parm_2048 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M2048);
shared_ptr<ILParams> parm_4096 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M4096);
shared_ptr<ILParams> parm_8192 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M8192);
shared_ptr<ILParams> parm_16384 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M16384);
shared_ptr<ILParams> parm_32768 = ElemParamFactory::GenElemParams<ILParams,BigInteger>(M32768);

shared_ptr<ILParams> parmArray[] = {
parm_16,
parm_1024,
parm_2048,
parm_4096,
parm_8192,
parm_16384,
parm_32768,
};

shared_ptr<ILNativeParams> nparm_16 = ElemParamFactory::GenElemParams<ILNativeParams,NativeInteger>(M16);
shared_ptr<ILNativeParams> nparm_1024 = ElemParamFactory::GenElemParams<ILNativeParams,NativeInteger>(M1024);
shared_ptr<ILNativeParams> nparm_2048 = ElemParamFactory::GenElemParams<ILNativeParams,NativeInteger>(M2048);
shared_ptr<ILNativeParams> nparm_4096 = ElemParamFactory::GenElemParams<ILNativeParams,NativeInteger>(M4096);

shared_ptr<ILNativeParams> nparmArray[] = {
nparm_16,
nparm_1024,
nparm_2048,
nparm_4096,
//nparm_8192,
//nparm_16384,
//nparm_32768,
};

#define DO_PARM_BENCHMARK(X) \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(0); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(3); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(4); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(5); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(6);

#define DO_NATIVEPARM_BENCHMARK(X) \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("nparm_16")->Arg(0); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("nparm_1024")->Arg(1); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("nparm_2048")->Arg(2); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("nparm_4096")->Arg(3); 


#define DO_PARM_BENCHMARK_TEMPLATE(X,Y) \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16")->Arg(0); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024")->Arg(1); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048")->Arg(2); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096")->Arg(3); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192")->Arg(4); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16384")->Arg(5); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32768")->Arg(6);

#define DO_NATIVEPARM_BENCHMARK_TEMPLATE(X,Y) \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("nparm_16")->Arg(0); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("nparm_1024")->Arg(1); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("nparm_2048")->Arg(2); \
		BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("nparm_4096")->Arg(3); 

