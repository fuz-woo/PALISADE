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
  This code benchmarks functions of the math directory  of the PALISADE lattice encryption library.

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

#include "vechelper.h"
#include "ElementParmsHelper.h"

using namespace std;
using namespace lbcrypto;

// add
static void add_BBVNative(benchmark::State& state) {
	state.PauseTiming();
	NativeVector a = makeNativeVector(nparmArray[state.range(0)]);
	NativeVector b = makeNativeVector(nparmArray[state.range(0)]);
	state.ResumeTiming();

	a = a+b;
}

static void BM_BBVNative_Addition(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		add_BBVNative(state);
	}
}

DO_NATIVEPARM_BENCHMARK(BM_BBVNative_Addition)

// +=
static void addeq_BBVNative(benchmark::State& state) {
	state.PauseTiming();
	NativeVector a = makeNativeVector(nparmArray[state.range(0)]);
	NativeVector b = makeNativeVector(nparmArray[state.range(0)]);
	state.ResumeTiming();

	a += b;
}

static void BM_BBVNative_AddEq(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		addeq_BBVNative(state);
	}
}

DO_NATIVEPARM_BENCHMARK(BM_BBVNative_AddEq)

// mult
static void mult_BBVNative(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeVector a = makeNativeVector(nparmArray[state.range(0)]);
	NativeVector b = makeNativeVector(nparmArray[state.range(0)]);
	state.ResumeTiming();

	a = a*b;
}

static void BM_BBVNative_Multiplication(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		mult_BBVNative(state);
	}
}

DO_NATIVEPARM_BENCHMARK(BM_BBVNative_Multiplication)

// *=
static void multeq_BBVNative(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeVector a = makeNativeVector(nparmArray[state.range(0)]);
	NativeVector b = makeNativeVector(nparmArray[state.range(0)]);
	state.ResumeTiming();

	a *= b;
}

static void BM_BBVNative_MultEq(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		multeq_BBVNative(state);
	}
}

DO_NATIVEPARM_BENCHMARK(BM_BBVNative_MultEq)

//execute the benchmarks
BENCHMARK_MAIN()
