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


/* this is an example of very basic google benchmarks
   all the benchmarks have
             no input parameters
	     cannot runover differnt length operations
	     some generate an output
  future examples will show the use of fixtures and templates to reduce
  the amount of 
  code needed

  for documentation on google benchmarks see https://github.com/google/benchmark
  as well as example code in the benchmark/examples directory

  note to increase the number of iterations call it as follows
             ./BBVNativeMath --benchmark_min_time=4.0


  increase the min_time (as a float) to increase the # iterations

 */


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

#include "BBVhelper.h"
#include "ElementParmsHelper.h"

using namespace std;
using namespace lbcrypto;

// add
static void add_BBVNative(benchmark::State& state) {
	state.PauseTiming();
	native_int::BigVector a = makeNativeVector(parmArray[state.range(0)]);
	native_int::BigVector b = makeNativeVector(parmArray[state.range(0)]);
	state.ResumeTiming();

	native_int::BigVector c1 = a+b;
}

static void BM_BBVNative_Addition(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		add_BBVNative(state);
	}
}

DO_PARM_BENCHMARK(BM_BBVNative_Addition)

// add
static void mult_BBVNative(benchmark::State& state) {	// function
	state.PauseTiming();
	native_int::BigVector a = makeNativeVector(parmArray[state.range(0)]);
	native_int::BigVector b = makeNativeVector(parmArray[state.range(0)]);
	state.ResumeTiming();

	native_int::BigVector c1 = a*b;
}

static void BM_BBVNative_Multiplication(benchmark::State& state) { // benchmark

	while (state.KeepRunning()) {
		mult_BBVNative(state);
	}
}

DO_PARM_BENCHMARK(BM_BBVNative_Multiplication)

//execute the benchmarks
BENCHMARK_MAIN()
