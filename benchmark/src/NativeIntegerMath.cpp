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

using namespace std;
using namespace lbcrypto;

//four simple benchmarks to test constructing BBIs
// typically the code to benchmark is in a 'function' that is then
// called within the actual benchmark.

// test BBI constants
static void make_NativeInt_constants(void) {	// function
	NativeInteger one(1);
}

void BM_NativeInt_constants(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
		make_NativeInt_constants();		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}
}

BENCHMARK(BM_NativeInt_constants);		// register benchmark

// make variables
static NativeInteger smalla("10403"), smallb("103");
static NativeInteger largea("4294967295"), largeb("4294967");

static void make_NativeInt_small_variables (void) {	// function
	NativeInteger a("10403"), b("103");
}


void BM_NativeInt_small_variables(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
		make_NativeInt_small_variables();		// note even with -O3 it appears
		// this is not optimized out
		// though check with your compiler
	}
}

BENCHMARK(BM_NativeInt_small_variables);		// register benchmark


static void make_NativeInt_large_variables (void) {	// function
	NativeInteger a("9446744073709551616"), b("9446744073709551617");
}

void BM_NativeInt_large_variables(benchmark::State& state) { // benchmark
	while (state.KeepRunning()) {
		make_NativeInt_large_variables();
	}
}

BENCHMARK(BM_NativeInt_large_variables);

// add
static void add_NativeInt(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeInteger& a = state.range(0) == 0 ? smalla : largea;
	NativeInteger& b = state.range(0) == 0 ? smallb : largeb;
	state.ResumeTiming();

	NativeInteger c = a+b;
}

static void BM_NativeInt_Addition(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		add_NativeInt(state);
	}
}

BENCHMARK(BM_NativeInt_Addition)->ArgName("Small")->Arg(0);
BENCHMARK(BM_NativeInt_Addition)->ArgName("Large")->Arg(1);

// +=
static void addeq_NativeInt(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeInteger a = state.range(0) == 0 ? smalla : largea;
	NativeInteger b = state.range(0) == 0 ? smallb : largeb;
	state.ResumeTiming();

	a += b;
}

static void BM_NativeInt_Addeq(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		addeq_NativeInt(state);
	}
}

BENCHMARK(BM_NativeInt_Addeq)->ArgName("Small")->Arg(0);
BENCHMARK(BM_NativeInt_Addeq)->ArgName("Large")->Arg(1);

// mult
static void mult_NativeInt(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeInteger& a = state.range(0) == 0 ? smalla : largea;
	NativeInteger& b = state.range(0) == 0 ? smallb : largeb;
	state.ResumeTiming();

	NativeInteger c = a*b;
}

static void BM_NativeInt_Mult(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		mult_NativeInt(state);
	}
}

BENCHMARK(BM_NativeInt_Mult)->ArgName("Small")->Arg(0);
BENCHMARK(BM_NativeInt_Mult)->ArgName("Large")->Arg(1);

// *=
static void multeq_NativeInt(benchmark::State& state) {	// function
	state.PauseTiming();
	NativeInteger a = state.range(0) == 0 ? smalla : largea;
	NativeInteger b = state.range(0) == 0 ? smallb : largeb;
	state.ResumeTiming();

	a *= b;
}

static void BM_NativeInt_Multeq(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		multeq_NativeInt(state);
	}
}

BENCHMARK(BM_NativeInt_Multeq)->ArgName("Small")->Arg(0);
BENCHMARK(BM_NativeInt_Multeq)->ArgName("Large")->Arg(1);

//execute the benchmarks
BENCHMARK_MAIN()
