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
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "../../src/core/lib/lattice/dcrtpoly.h"
#include "utils/utilities.h"

#include <vector>

#include "vechelper.h"
#include "ElementParmsHelper.h"

using namespace std;
using namespace lbcrypto;

// test scenarios
struct Scenario {
	usint bits;
	usint m;
	string modulus;
	string rootOfUnity;
} Scenarios[] = {
		{
				503,
				2048,
				"13093562431584567480052758787310396608866568184172259157933165472384535185618698219533080369303616628603546736510240284036869026183541572213314110873601",
				"12023848463855649466660377440069556144464267030949365165993725942220441412632799311989973938254823071405336623315668961501139592673000297887682895033094"
		},
		{
				132,
				8192,
				"2722258935367507707706996859454146142209",
				"1426115470453457649704739287701063827541"
		},
};

static shared_ptr<ILParams> generate_IL_parms(int s) {
	return shared_ptr<ILParams>( new ILParams(Scenarios[s].m, BigInteger(Scenarios[s].modulus), BigInteger(Scenarios[s].rootOfUnity)) );
}

static const usint smbits = 28;

static shared_ptr<ILDCRTParams<BigInteger>> generate_DCRT_parms(int s) {
	usint nTowers = Scenarios[s].bits/smbits;

	vector<NativeInteger> moduli(nTowers);
	vector<NativeInteger> rootsOfUnity(nTowers);

	NativeInteger q = FirstPrime<NativeInteger>(smbits, Scenarios[s].m);
	NativeInteger temp;
	BigInteger modulus(1);

	for(usint i=0; i < nTowers; i++){
		moduli[i] = q;
		rootsOfUnity[i] = RootOfUnity(Scenarios[s].m,moduli[i]);
		modulus = modulus * BigInteger(moduli[i]);
		q = NextPrime(q, Scenarios[s].m);
	}

	return shared_ptr<ILDCRTParams<BigInteger>>( new ILDCRTParams<BigInteger>(Scenarios[s].m, moduli, rootsOfUnity) );
}

// statically construct 'em
vector<shared_ptr<ILParams>> vparms = { generate_IL_parms(0), generate_IL_parms(1) };
vector<shared_ptr<ILDCRTParams<BigInteger>>> vaparms = { generate_DCRT_parms(0), generate_DCRT_parms(1) };

template <class E>
static void make_LATTICE_empty(shared_ptr<typename E::Params>& params) {
	E v1(params);
}

template <class E>
void BM_LATTICE_empty(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_LATTICE_empty<E>(parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_LATTICE_empty,Poly)

template <class E>
static E makeElement(shared_ptr<ILParams> params) {
	BigVector vec = makeVector(params);
	E			elem(params);
	elem.SetValues(vec, elem.GetFormat());
	return std::move(elem);
}

template <class E>
static E makeElement(shared_ptr<ILDCRTParams<BigInteger>> p) {
	shared_ptr<ILParams> params( new ILParams( p->GetCyclotomicOrder(), p->GetModulus(), 1) );
	BigVector vec = makeVector(params);

	Poly bigE(params);
	bigE.SetValues(vec, bigE.GetFormat());

	E			elem(bigE, p);
	return std::move(elem);
}

vector<Poly> vectors[] = {
		{ makeElement<Poly>(vparms[0]), makeElement<Poly>(vparms[0]) },
		{ makeElement<Poly>(vparms[1]), makeElement<Poly>(vparms[1]) },
};

vector<DCRTPoly> avectors[] = {
		{ makeElement<DCRTPoly>(vaparms[0]), makeElement<DCRTPoly>(vaparms[0]) },
		{ makeElement<DCRTPoly>(vaparms[1]), makeElement<DCRTPoly>(vaparms[1]) },
};

// make variables

template <class E>
static void make_LATTICE_vector (benchmark::State& state, shared_ptr<typename E::Params>& params) {	// function
	E			elem = makeElement<E>(params);
}

template <class E>
void BM_LATTICE_vector(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_LATTICE_vector<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_LATTICE_vector,Poly)

// plus
template <class E>
static void add_LATTICE(benchmark::State& state, shared_ptr<typename E::Params> params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	E			b = makeElement<E>(params);
	state.ResumeTiming();

	E c1 = a+b;
}

template <class E>
static void BM_add_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		add_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_add_LATTICE,Poly)

void BM_add_LATTICEARRAY(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	if( state.range(0) == 0 ) {
		while (state.KeepRunning()) {
			Poly sum = vectors[state.range(1)][0] + vectors[state.range(1)][1];
		}
	}
	else {
		while (state.KeepRunning()) {
			DCRTPoly sum = avectors[state.range(1)][0] + avectors[state.range(1)][1];
		}
	}
}

BENCHMARK(BM_add_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,0});
BENCHMARK(BM_add_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,1});
BENCHMARK(BM_add_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,0});
BENCHMARK(BM_add_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,1});

// plus=
template <class E>
static void addeq_LATTICE(benchmark::State& state, shared_ptr<typename E::Params> params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	E			b = makeElement<E>(params);
	state.ResumeTiming();

	a += b;
}

template <class E>
static void BM_addeq_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		addeq_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_addeq_LATTICE,Poly)

void BM_addeq_LATTICEARRAY(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	if( state.range(0) == 0 ) {
		while (state.KeepRunning()) {
			vectors[state.range(1)][0] += vectors[state.range(1)][1];
		}
	}
	else {
		while (state.KeepRunning()) {
			avectors[state.range(1)][0] += avectors[state.range(1)][1];
		}
	}
}

BENCHMARK(BM_addeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,0});
BENCHMARK(BM_addeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,1});
BENCHMARK(BM_addeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,0});
BENCHMARK(BM_addeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,1});

template <class E>
static void mult_LATTICE(benchmark::State& state, shared_ptr<typename E::Params>& params) {	// function
	state.PauseTiming();
	E			a = makeElement<E>(params);
	E			b = makeElement<E>(params);
	state.ResumeTiming();

	E c1 = a*b;
}

template <class E>
static void BM_mult_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		mult_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_mult_LATTICE,Poly)

void BM_mult_LATTICEARRAY(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	if( state.range(0) == 0 ) {
		while (state.KeepRunning()) {
			Poly sum = vectors[state.range(1)][0] * vectors[state.range(1)][1];
		}
	}
	else {
		while (state.KeepRunning()) {
			DCRTPoly sum = avectors[state.range(1)][0] * avectors[state.range(1)][1];
		}
	}
}

BENCHMARK(BM_mult_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,0});
BENCHMARK(BM_mult_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,1});
BENCHMARK(BM_mult_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,0});
BENCHMARK(BM_mult_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,1});

template <class E>
static void multeq_LATTICE(benchmark::State& state, shared_ptr<typename E::Params>& params) {	// function
	state.PauseTiming();
	E			a = makeElement<E>(params);
	E			b = makeElement<E>(params);
	state.ResumeTiming();

	a *= b;
}

template <class E>
static void BM_multeq_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		multeq_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_mult_LATTICE,Poly)

void BM_multeq_LATTICEARRAY(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	if( state.range(0) == 0 ) {
		while (state.KeepRunning()) {
			vectors[state.range(1)][0] *= vectors[state.range(1)][1];
		}
	}
	else {
		while (state.KeepRunning()) {
			avectors[state.range(1)][0] *= avectors[state.range(1)][1];
		}
	}
}

BENCHMARK(BM_multeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,0});
BENCHMARK(BM_multeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("Poly/scenario")->Args({0,1});
BENCHMARK(BM_multeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,0});
BENCHMARK(BM_multeq_LATTICEARRAY)->Unit(benchmark::kMicrosecond)->ArgName("DCRTPoly/scenario")->Args({1,1});

template <class E>
static void switchformat_LATTICE(benchmark::State& state, shared_ptr<typename E::Params>& params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	state.ResumeTiming();

	a.SwitchFormat();
}

template <class E>
static void BM_switchformat_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		switchformat_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_switchformat_LATTICE,Poly)

template <class E>
static void doubleswitchformat_LATTICE(benchmark::State& state, shared_ptr<typename E::Params>& params) {
	state.PauseTiming();
	E			a = makeElement<E>(params);
	state.ResumeTiming();

	a.SwitchFormat();
	a.SwitchFormat();
}

template <class E>
static void BM_doubleswitchformat_LATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		doubleswitchformat_LATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_doubleswitchformat_LATTICE,Poly)

//execute the benchmarks
BENCHMARK_MAIN()
