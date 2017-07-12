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
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "lattice/dcrtpoly.h"
#include "utils/utilities.h"

#include <vector>

#include "BBVhelper.h"
#include "ElementParmsHelper.h"

using namespace std;
using namespace lbcrypto;

typedef ILParamsImpl<native_int::BigInteger> ILNativeParams;
typedef PolyImpl< native_int::BigInteger, native_int::BigInteger, native_int::BigVector, ILNativeParams > PolyNative2n;

template <class E>
static void make_NATIVELATTICE_empty(shared_ptr<ILParams>& params) {
	shared_ptr<ILNativeParams> nparams(
			new ILNativeParams(params->GetCyclotomicOrder(),
					params->GetModulus().ConvertToInt(),
					params->GetRootOfUnity().ConvertToInt()) );
	E v1(nparams);
}

template <class E>
void BM_NATIVELATTICE_empty(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_NATIVELATTICE_empty<E>(parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_NATIVELATTICE_empty,PolyNative2n)

template <class E>
static E makeElement(benchmark::State& state, shared_ptr<ILParams> params) {
	shared_ptr<ILNativeParams> nparams(
			new ILNativeParams(params->GetCyclotomicOrder(),
					params->GetModulus().ConvertToInt(),
					params->GetRootOfUnity().ConvertToInt()) );
	native_int::BigVector vec = makeNativeVector(params);
	E			elem(nparams);
	elem.SetValues(vec, elem.GetFormat());
	return std::move(elem);
}

// make variables

template <class E>
static void make_NATIVELATTICE_vector (benchmark::State& state, shared_ptr<ILParams>& params) {	// function
	E			elem = makeElement<E>(state, params);
}

template <class E>
void BM_NATIVELATTICE_vector(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		make_NATIVELATTICE_vector<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_NATIVELATTICE_vector,PolyNative2n)

// add
template <class E>
static void add_NATIVELATTICE(benchmark::State& state, shared_ptr<ILParams> params) {
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	E			b = makeElement<E>(state, params);
	state.ResumeTiming();

	E c1 = a+b;
}

template <class E>
static void BM_add_NATIVELATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		add_NATIVELATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_add_NATIVELATTICE,PolyNative2n)

template <class E>
static void mult_NATIVELATTICE(benchmark::State& state, shared_ptr<ILParams>& params) {	// function
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	E			b = makeElement<E>(state, params);
	state.ResumeTiming();

	E c1 = a*b;
}

template <class E>
static void BM_mult_NATIVELATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		mult_NATIVELATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_mult_NATIVELATTICE,PolyNative2n)

template <class E>
static void switchformat_NATIVELATTICE(benchmark::State& state, shared_ptr<ILParams>& params) {
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	state.ResumeTiming();

	a.SwitchFormat();
}

template <class E>
static void BM_switchformat_NATIVELATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		switchformat_NATIVELATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_switchformat_NATIVELATTICE,PolyNative2n)

template <class E>
static void doubleswitchformat_NATIVELATTICE(benchmark::State& state, shared_ptr<ILParams>& params) {
	state.PauseTiming();
	E			a = makeElement<E>(state, params);
	state.ResumeTiming();

	a.SwitchFormat();
	a.SwitchFormat();
}

template <class E>
static void BM_doubleswitchformat_NATIVELATTICE(benchmark::State& state) { // benchmark
	if( state.thread_index == 0 ) {
		;
	}

	while (state.KeepRunning()) {
		doubleswitchformat_NATIVELATTICE<E>(state, parmArray[state.range(0)]);
	}
}

DO_PARM_BENCHMARK_TEMPLATE(BM_doubleswitchformat_NATIVELATTICE,PolyNative2n)

//execute the benchmarks
BENCHMARK_MAIN()
