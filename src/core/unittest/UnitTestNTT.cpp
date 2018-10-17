/*
 * @file 
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
This code tests the transform feature of the PALISADE lattice encryption library.

Test cases in this file make the following assumptions:
1. All functionatliy of plaintext (both BytePlainTextEncoding and IntPlainTextEncoding) work.
2. Encrypt/Decrypt work
3. Math layer operations such as functions in nbtheory
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "lattice/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

template<typename Element>
void switch_format_simple_single_crt(const string& msg) {
	using Params = typename Element::Params;

	usint m1 = 16;

	typename Element::Integer modulus = FirstPrime<typename Element::Integer>(22, m1);
	typename Element::Integer rootOfUnity(RootOfUnity(m1, modulus));
	Params params(m1, modulus, rootOfUnity);
	Params params2(m1 / 2, modulus, rootOfUnity);
	shared_ptr<Params> x1p( new Params(params) );
	shared_ptr<Params> x2p( new Params(params2) );

	Element x1( x1p, Format::COEFFICIENT );
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	Element x2( x2p, Format::COEFFICIENT );
	x2 = { 4127,9647,1987,5410 };

	Element x1Clone(x1);
	Element x2Clone(x2);

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	EXPECT_EQ(x1, x1Clone) << msg;
	EXPECT_EQ(x2, x2Clone) << msg;
}

TEST(UTNTT, switch_format_simple_single_crt) {
	RUN_ALL_POLYS(switch_format_simple_single_crt, "switch_format_simple_single_crt")
}

template<typename Element>
void switch_format_simple_double_crt(const string& msg) {
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(28, init_m);
	NativeInteger temp;
	typename Element::Integer modulus(1);

	for (size_t i = 0; i < init_size; i++) {
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
		modulus = modulus * typename Element::Integer(init_moduli[i].ConvertToInt());
		q = NextPrime(q, init_m);
	}

	DiscreteGaussianGeneratorImpl<typename Element::Vector> dgg(init_stdDev);

	shared_ptr<ILDCRTParams<typename Element::Integer>> params( new ILDCRTParams<typename Element::Integer>(init_m, init_moduli, init_rootsOfUnity) );

	Element x1(params, Format::COEFFICIENT);
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	Element x2(params, Format::COEFFICIENT);
	x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

	Element x1Clone(x1);
	Element x2Clone(x2);

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	EXPECT_EQ(x1, x1Clone) << msg;
	EXPECT_EQ(x2, x2Clone) << msg;
}

TEST(UTNTT, switch_format_simple_double_crt) {
	RUN_BIG_DCRTPOLYS(switch_format_simple_double_crt, "switch_format_simple_double_crt")
}

template<typename Element>
void switch_format_decompose_single_crt(const string& msg) {
	using Params = typename Element::Params;

	bool dbg_flag = false;
	usint m1 = 16;

	typename Element::Integer modulus = FirstPrime<typename Element::Integer>(22, m1);
	typename Element::Integer rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<Params> params( new Params(m1, modulus, rootOfUnity) );
	shared_ptr<Params> params2( new Params(m1 / 2, modulus, rootOfUnity) );

	Element x1(params, Format::COEFFICIENT);
	x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

	Element x2(params, Format::COEFFICIENT);
	x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

	x1.SwitchFormat(); //EVAL
	x2.SwitchFormat();

	x1.SwitchFormat(); //COEF
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	x1.SwitchFormat(); //COEf
	x2.SwitchFormat();

	x1.SwitchFormat(); //EVAL
	x2.SwitchFormat();

	Element x1Expected(params2, Format::COEFFICIENT);
	x1Expected = { 431,1234,2145,5471};

	Element x2Expected(params2, Format::COEFFICIENT);
	x2Expected = { 4127,1987,6541,9741 };

	DEBUG("x1: "<<x1);
	DEBUG("x1p: "<<*x1.GetParams());
	DEBUG("x1exp: "<<x1Expected);
	DEBUG("x1exppp: "<<*x1Expected.GetParams());

	DEBUG("x2: "<<x2);
	DEBUG("x2exp: "<<x2Expected);

	EXPECT_EQ(x1, x1Expected) << msg;
	EXPECT_EQ(x2, x2Expected) << msg;
}

TEST(UTNTT, switch_format_decompose_single_crt) {
	RUN_ALL_POLYS(switch_format_decompose_single_crt, "switch_format_decompose_single_crt")
}

template<typename Element>
void decomposeMult_double_crt(const string& msg) {
  bool dbg_flag = false;
	usint init_m = 16;

	float init_stdDev = 4;

	usint init_size = 2;

	vector<NativeInteger> init_moduli(init_size);

	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger temp;
	
	init_moduli[0] = NativeInteger("17729");
	init_moduli[1] = NativeInteger("17761");


	for (size_t i = 0; i < init_size; i++) {
		init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
	}

	DiscreteGaussianGeneratorImpl<typename Element::Vector> dgg(init_stdDev);

	shared_ptr<ILDCRTParams<typename Element::Integer>> params( new ILDCRTParams<typename Element::Integer>(init_m, init_moduli, init_rootsOfUnity) );

	Element x1(params, Format::COEFFICIENT);
	x1 = { 0,0,0,0,0,0,1,0 };

	Element x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	Element resultsEval(x2.CloneParametersOnly());
	resultsEval = { 0,0,0,0,0,0,0,0 };
	resultsEval.SwitchFormat();

	x1.SwitchFormat();
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	x1.SwitchFormat();
	x2.SwitchFormat();

	resultsEval = x1*x2;

	resultsEval.SwitchFormat(); // COEF


	DEBUG("resultsEval ix 0: "<<resultsEval.GetElementAtIndex(0).GetValues());
	DEBUG("resultsEval ix 1: "<<resultsEval.GetElementAtIndex(1).GetValues());

	EXPECT_EQ(resultsEval.GetElementAtIndex(0).at(0), 0) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).at(1), 0) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).at(2), NativeInteger("17728")) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(0).at(3), 0) << msg;

	EXPECT_EQ(resultsEval.GetElementAtIndex(1).at(0), 0) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).at(1), 0) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).at(2), NativeInteger("17760")) << msg;
	EXPECT_EQ(resultsEval.GetElementAtIndex(1).at(3), 0) << msg;
}

TEST(UTNTT, decomposeMult_double_crt) {
	RUN_BIG_DCRTPOLYS(decomposeMult_double_crt, "decomposeMult_double_crt")
}

template<typename Element>
void decomposeMult_single_crt(const string& msg) {
	using Params = typename Element::Params;

  bool dbg_flag = false;
	usint m1 = 16;

	typename Element::Integer modulus("17729");
	typename Element::Integer rootOfUnity(RootOfUnity(m1, modulus));
	shared_ptr<Params> params( new Params(m1, modulus, rootOfUnity) );
	shared_ptr<Params> params2( new Params(m1 / 2, modulus, rootOfUnity) );

	Element x1(params, Format::COEFFICIENT);

	x1 = { 0,0,0,0,0,0,1,0 };

	Element x2(params, Format::COEFFICIENT);
	x2 = { 0,0,0,0,0,0,1,0 };

	x1.SwitchFormat(); //dbc remember to remove these.
	x2.SwitchFormat();
	x1.SwitchFormat();
	x2.SwitchFormat();

	x1.Decompose();
	x2.Decompose();

	DEBUG("x1.Decompose() "<<x1.GetValues());
	DEBUG("x2.Decompose() "<<x2.GetValues());

	Element resultsEval(params2, Format::EVALUATION);
	DEBUG("resultsEval.modulus"<< resultsEval.GetModulus());

	x1.SwitchFormat();
	x2.SwitchFormat();

	DEBUG("x1.SwitchFormat() "<<x1.GetValues());
	DEBUG("x2.SwitchFormat() "<<x2.GetValues());

	resultsEval = x1*x2;
	DEBUG("resultsEval.eval "<<resultsEval.GetValues());

	resultsEval.SwitchFormat(); // COEF	
	DEBUG("resultsEval.coef "<<resultsEval.GetValues());
	DEBUG("resultsEval.modulus"<< resultsEval.GetModulus());

	EXPECT_EQ(resultsEval.at(0), typename Element::Integer(0)) << msg;
	EXPECT_EQ(resultsEval.at(1), typename Element::Integer(0)) << msg;
	EXPECT_EQ(resultsEval.at(2), typename Element::Integer("17728")) << msg;
	EXPECT_EQ(resultsEval.at(3), typename Element::Integer(0)) << msg;
}

TEST(UTNTT, decomposeMult_single_crt) {
	RUN_ALL_POLYS(decomposeMult_single_crt, "decomposeMult_single_crt")
}
