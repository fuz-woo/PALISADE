/*
 * LatticeCompare.cpp
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
  This code benchmarks functions of the src/lib/lattoce directory  of the PALISADE lattice encryption library.
 */

#include "benchmark/benchmark_api.h"

#include <iostream>
#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "../../src/core/lib/lattice/dcrtpoly.h"
#include "utils/utilities.h"

#include <vector>

#include "BBVhelper.h"
#include "ElementParmsHelper.h"

#include "lattice/ilparams.cpp"
#include "../../src/core/lib/lattice/poly.cpp"
#include "math/transfrm.cpp"
#include "math/discretegaussiangenerator.cpp"
#include "math/discreteuniformgenerator.cpp"
#include "math/binaryuniformgenerator.cpp"
#include "math/ternaryuniformgenerator.cpp"

using namespace std;
using namespace lbcrypto;

typedef native_int::BigInteger nativeInt;
typedef native_int::BigVector nativeVec;
typedef native_int::ILParams nativeParams;

//typedef cpu_int::BigInteger<uint32_t,64>  smallInt32_64;
////template class cpu_int::BigInteger<uint32_t,64>;
//template class cpu_int::BigVectorImpl<smallInt32_64>;
//
//typedef cpu_int::BigInteger<uint32_t,128>  smallInt32_128;
////template class cpu_int::BigInteger<uint32_t,128>;
//template class cpu_int::BigVectorImpl<smallInt32_128>;

map<int,map<int,string>> primes;
map<int,map<int,string>> roots;

bool ranloadprimes = false;
void
loadprimes()
{
	if( ranloadprimes ) return;
	ranloadprimes = true;
	for( int mbits = 30; mbits <= 60; mbits *= 2 ) {
		for( int n = 1024; n <=8192; n *= 2 ) {
			primes[n][mbits] = FirstPrime<BigInteger>(mbits, n).ToString();
			roots[n][mbits] = RootOfUnity<BigInteger>(n, BigInteger(primes[n][mbits])).ToString();
		}
	}
}

static void CustomArguments(benchmark::internal::Benchmark* b) {
	for( int n = 1024; n <=8192; n *= 2 ) {
		for( int mbits = 30; mbits <= 60; mbits *= 2 ) {
			b->Args({n, mbits});
		}
	}
}
//should really be ModType,IntType
//then PolyImpl<> becomes PolyType from poly.h

template <typename IntType, typename VecType, typename ParamType>
static PolyImpl<IntType,IntType,VecType,ParamType> makeElement(benchmark::State& state) {
	int n = state.range(0);
	int w = state.range(1);
	shared_ptr<ParamType> params( new ParamType(n, IntType(primes[n][w]), IntType(roots[n][w])) );
	VecType vec(params->GetCyclotomicOrder()/2, params->GetModulus());
	PolyImpl<IntType,IntType,VecType,ParamType>	elem(params);
	elem.SetValues(vec, elem.GetFormat());
	return std::move(elem);
}

// add
template <typename IntType, typename VecType, typename ParamType>
static void add_LATTICE(benchmark::State& state) {
	state.PauseTiming();
	loadprimes();
	PolyImpl<IntType,IntType,VecType,ParamType>	a = makeElement<IntType, VecType, ParamType>(state);
	PolyImpl<IntType,IntType,VecType,ParamType>	b = makeElement<IntType, VecType,ParamType>(state);
	state.ResumeTiming();

	PolyImpl<IntType,IntType,VecType,ParamType> c1 = a+b;
}

template <class E, class V, class P>
static void BM_add_LATTICE(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
	  add_LATTICE<E,V,P>(state);
	}
}

BENCHMARK_TEMPLATE(BM_add_LATTICE,nativeInt, nativeVec, nativeParams )->Apply(CustomArguments);
BENCHMARK_TEMPLATE(BM_add_LATTICE,BigInteger, BigVector, ILParams)->Apply(CustomArguments);

template <class IntType, class VecType, typename ParamType>
static void mult_LATTICE(benchmark::State& state) {	// function
	state.PauseTiming();
	loadprimes();
	PolyImpl<IntType,IntType,VecType,ParamType>	a = makeElement<IntType,VecType,ParamType>(state);
	PolyImpl<IntType,IntType,VecType,ParamType>	b = makeElement<IntType,VecType,ParamType>(state);
	state.ResumeTiming();

	PolyImpl<IntType,IntType,VecType,ParamType> c1 = a*b;
}

template <class E, class V, class P>
static void BM_mult_LATTICE(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
	  mult_LATTICE<E,V,P>(state);
	}
}

BENCHMARK_TEMPLATE(BM_mult_LATTICE,nativeInt,nativeVec,nativeParams)->Apply(CustomArguments);
BENCHMARK_TEMPLATE(BM_mult_LATTICE,BigInteger,BigVector,ILParams)->Apply(CustomArguments);

template <class IntType, class VecType, class ParamType>
static void switchformat_LATTICE(benchmark::State& state) {
	state.PauseTiming();
	loadprimes();
	PolyImpl<IntType,IntType,VecType,ParamType>	a = makeElement<IntType,VecType,ParamType>(state);
	state.ResumeTiming();

	a.SwitchFormat();
}

template <class E, class V, class P>
static void BM_switchformat_LATTICE(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
	  switchformat_LATTICE<E,V,P>(state);
	}
}

BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,nativeInt,nativeVec,nativeParams)->Apply(CustomArguments);
BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,BigInteger,BigVector,ILParams)->Apply(CustomArguments);

//execute the benchmarks
BENCHMARK_MAIN()
