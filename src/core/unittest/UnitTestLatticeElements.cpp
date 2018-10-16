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
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <vector>

#include "math/backend.h"
#include "lattice/backend.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "utils/parmfactory.h"
#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;

void testDCRTPolyConstructorNegative(std::vector<NativePoly> &towers);

/*-TESTING METHODS OF LATTICE ELEMENTS    ----------------*/

// template for operations tests
template<typename Element>
static void operators_tests(const string& msg) {

	using VecType = typename Element::Vector;

	usint m = 8;
	shared_ptr<typename Element::Params> ilparams = ElemParamFactory::GenElemParams<typename Element::Params>(m);
	//GenerateDCRTParams<typename Element::Integer>(8, 3, 20) );

	Element ilvector2n1(ilparams);
	ilvector2n1 = {1,2,0,1};

	Element ilvector2n2(ilparams);
	ilvector2n2 = {1,2,0,1};

	EXPECT_EQ(ilvector2n1, ilvector2n2) << msg << " Failure: Operator ==";

	{//test constructor
		Element ilv1(ilvector2n1);
		EXPECT_EQ(ilvector2n1, ilv1) << msg << " Failure: copy constructor";
	}

	{//test operator=
		Element ilv1 = ilvector2n1;
		EXPECT_EQ(ilvector2n1, ilv1) << msg << " Failure: operator=";
	}

	{//test SwitchModulus, !=
		Element ilv1 = ilvector2n1;
		try {
			ilv1.SwitchModulus(typename VecType::Integer("123467"), typename VecType::Integer("1234"));
			EXPECT_NE(ilvector2n1, ilv1)
				<< msg << " Failure: Operator!= switchmodulus comparison";

			Element ilv2 = ilvector2n1;
			ilv2.at(2)= 2;
			EXPECT_NE(ilvector2n1, ilv2)
				<< msg << " Failure: Operator!= value comparison";
		} catch (std::exception& e) {
			// ignore for dcrtpoly
		}
	}

	// FIXME
#ifdef OUT
	NOTE at not supported for dcrtpoly; needs a fix
	{//test operator-=
		Element ilv1 = ilvector2n1;
		ilv1 -= ilvector2n1;
		for (usint i = 0; i < m/2; ++i) {
			EXPECT_EQ(0, ilv1.at(i))
				<< "Faiure: Operator-= @ index "<<i;
		}
	}

	{//test operator+=
		Element ilv1 = ilvector2n1;
		ilv1 += ilvector2n1;
		for (usint i = 0; i < m/2; ++i)
			{//we expect a+a == 2*a
			EXPECT_EQ(2 * ilvector2n1.at(i),
				  ilv1.at(i))
				<< "Faiure: Operator+= @ index "<<i;
		}
	}

	SetValues and GetValues and etc not supported for dcrtpoly; needs a fix
	{//test getters //todo: this should be in its own test
		Element ilvector2n(ilparams);
		VecType bbv(m/2, ilparams->GetModulus());
		bbv = {"1", "2", "0", "1"};
		ilvector2n.SetValues(bbv, ilvector2n.GetFormat());
		bbv[3] = 11;
		EXPECT_EQ(ilparams->GetModulus(), ilvector2n.GetModulus())
			<< "Failure: GetModulus()";
		EXPECT_EQ(m, ilvector2n.GetCyclotomicOrder())
			<< "Failure: GetCyclotomicOrder()";
		EXPECT_EQ(ilparams->GetRootOfUnity(), ilvector2n.GetRootOfUnity())
			<< "Failure: GetRootOfUnity()";
		EXPECT_EQ(bbv, ilvector2n.GetValues()) 
			<< "Failure: GetValues()";
		EXPECT_EQ(Format::EVALUATION, ilvector2n.GetFormat())
			<< "Failure: GetFormat()";
		EXPECT_EQ(m/2, ilvector2n.GetLength())
			<< "Failure: GetLength()";

		 for (usint i = 0; i < m/2; ++i) {
		 	EXPECT_EQ(bbv.at(i), 
		 		  ilvector2n.at(i)) 
		 		<< " Failure: at("<<i<< ")";
		 }
	}
#endif
}

//instantiate ops_tests for various backend combos
TEST(UTPoly, ops_tests) {
	RUN_ALL_POLYS(operators_tests, "operators_tests")
}

TEST(UTDCRTPoly, ops_tests) {
	RUN_BIG_DCRTPOLYS(operators_tests, "operators_tests")
}

// template for rounding_operations tests
template<typename Element>
void rounding_operations(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

  bool dbg_flag = false;
	usint m = 8;

	typename VecType::Integer q("73");
	typename VecType::Integer primitiveRootOfUnity("22");
	typename VecType::Integer p("8");

	shared_ptr<ParmType> ilparams( new ParmType(m, q, primitiveRootOfUnity) );

	//temporary larger modulus that is used for polynomial multiplication before rounding
	typename VecType::Integer q2("16417");
	typename VecType::Integer primitiveRootOfUnity2("13161");

	shared_ptr<ParmType> ilparams2( new ParmType(m, q2, primitiveRootOfUnity2) );

	Element ilvector2n1(ilparams,COEFFICIENT);
	ilvector2n1 = { "31","21","15","34"};

	DEBUG("ilvector2n1 a "<<ilvector2n1);

	Element ilvector2n2(ilparams,COEFFICIENT);
	ilvector2n2 = { "21","11","35","32" };

	DEBUG("ilvector2n2 a "<<ilvector2n2);

	//unit test for MultiplyAndRound

	Element roundingCorrect1(ilparams, COEFFICIENT);
	roundingCorrect1 = { "3","2","2","4" };

	DEBUG("ilvector2n1 b "<<ilvector2n1);

	Element rounding1 = ilvector2n1.MultiplyAndRound(p, q);

	EXPECT_EQ(roundingCorrect1, rounding1) 
		<< msg << " Failure: Rounding p*polynomial/q";

	//unit test for MultiplyAndRound after a polynomial
	//multiplication using the larger modulus

	Element roundingCorrect2(ilparams2, COEFFICIENT);
	roundingCorrect2 = { "16316","16320","60","286" };

	ilvector2n1.SwitchModulus(q2, primitiveRootOfUnity2);
	ilvector2n2.SwitchModulus(q2, primitiveRootOfUnity2);
	DEBUG("ilvector2n1 c "<<ilvector2n1);
	DEBUG("ilvector2n2 c "<<ilvector2n2);


	ilvector2n1.SwitchFormat();
	ilvector2n2.SwitchFormat();
	DEBUG("ilvector2n1 d "<<ilvector2n1);
	DEBUG("ilvector2n2 d "<<ilvector2n2);

	Element rounding2 = ilvector2n1 * ilvector2n2;

	DEBUG("rounding2 d "<<rounding2);
	rounding2.SwitchFormat();
	DEBUG("rounding2 e "<<rounding2);
	rounding2 = rounding2.MultiplyAndRound(p, q);
	DEBUG("rounding2 f "<<rounding2);
	EXPECT_EQ(roundingCorrect2, rounding2) 
		<< msg << " Failure: Rounding p*polynomial1*polynomial2/q";

	//makes sure the result is correct after going back to the
	//original modulus

	rounding2.SwitchModulus(q, primitiveRootOfUnity);
	DEBUG("rounding2 g "<<rounding2);

	Element roundingCorrect3(ilparams, COEFFICIENT);
	roundingCorrect3 = { "45","49","60","67" };

	EXPECT_EQ(roundingCorrect3, rounding2) 
		<< msg << " Failure p*polynomial1*polynomial2/q (mod q)";
}

// instantiate various test for rounding_operations()
TEST(UTPoly, rounding_operations) {
	RUN_ALL_POLYS(rounding_operations, "rounding_operations");
}

// FIXME DCRTPoly needs an assignment op/ctor
//TEST(UTDCRTPoly, rounding_operations) {
//	rounding_operations<BigVector, ILDCRTParams, DCRTPoly>();
//}

//template for setters_tests()
template<typename Element>
void setters_tests(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint m = 8;

	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {	"3","0","0","0"};
	ilvector2n.SetValues(bbv, Format::COEFFICIENT);

	Element ilvector2nInEval(ilparams);
	VecType bbvEval(m/2, primeModulus);
	bbvEval={"3","3","3","3"};
	ilvector2nInEval.SetValues(bbvEval, Format::EVALUATION);

	{// test SetFormat()
		Element ilv(ilvector2n);

		ilv.SetFormat(Format::COEFFICIENT);
		EXPECT_EQ(ilvector2n, ilv) << msg << " Failure: SetFormat() to COEFFICIENT";

		ilv.SetFormat(Format::EVALUATION);
		EXPECT_EQ(ilvector2nInEval, ilv) << msg << " Failure: SetFormat() to EVALUATION";
	}

	// this is here because it's a vectors-only test
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		EXPECT_EQ(36, ilv.Norm())
			<< msg << " Failure: Norm()";
	}
}

// instantiate setters_tests() for various combos
TEST(UTPoly, setters_tests) {
	RUN_ALL_POLYS(setters_tests, "setters_tests");
}

// FIXME DCRTPoly? ^^^^^

//template for binary_ops()
template<typename Element>
void binary_ops(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	bool dbg_flag = false;
	usint m = 8;

	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1 = {"2","1","1","1"};
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());
	DEBUG("ilvector2n1 a "<<ilvector2n1);

	Element ilvector2n2(ilparams);
	VecType bbv2(m/2, primeModulus);
	bbv2 = {"1","0","1","1"};
	ilvector2n2.SetValues(bbv2, ilvector2n2.GetFormat());
	DEBUG("ilvector2n2 a "<<ilvector2n2);

	Element ilvector2n3(ilparams, COEFFICIENT);
	VecType bbv3(m / 2, primeModulus);
	bbv3 = {"2","1","1","1"};
	ilvector2n3.SetValues(bbv3, ilvector2n3.GetFormat());
	DEBUG("ilvector2n3 a "<<ilvector2n3);

	Element ilvector2n4(ilparams, COEFFICIENT);
	VecType bbv4(m / 2, primeModulus);
	bbv4 = {"1","0","1","1"};
	ilvector2n4.SetValues(bbv4, ilvector2n4.GetFormat());
	DEBUG("ilvector2n4 a "<<ilvector2n4);

	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 a "<<ilv1);
		Element ilv2 = ilv1.Plus(ilvector2n2);
		DEBUG("ilv2 a "<<ilv2);
		VecType expected(4, primeModulus);
		expected = {"3","1","2","2"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<< msg << " Failure: Plus()";
	}
	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 b "<<ilv1);
		Element ilv2 = ilv1.Minus(ilvector2n2);
		VecType expected(4, primeModulus);
		expected = {"1","1","0","0"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<< msg << " Failure: Minus()";
	}
	
	{
		Element ilv1(ilvector2n1);
		DEBUG("ilv1 c "<<ilv1);
		Element ilv2 = ilv1.Times(ilvector2n2);
		VecType expected(4, primeModulus);
		expected = {"2","0","1","1"};
		EXPECT_EQ(expected, ilv2.GetValues())
			<< msg << " Failure: Times()";
	}

	{
		ilvector2n3.SwitchFormat();
		DEBUG("ilvector2n3 "<<ilvector2n3);
		ilvector2n4.SwitchFormat();
		DEBUG("ilvector2n4 "<<ilvector2n4);

		Element ilv3(ilvector2n3);
		Element ilv4 = ilv3.Times(ilvector2n4);
		DEBUG("ilv3 "<<ilv3);
		DEBUG("ilv4 "<<ilv4);

		ilv4.SwitchFormat();
		DEBUG("ilv4 "<<ilv4);

		VecType expected(4, primeModulus);
		expected = {"0","72","2","4"};
		EXPECT_EQ(expected, ilv4.GetValues())
			<< msg << " Failure: Times() using SwitchFormat()";
	}
}

// Instantiations of binary_ops
TEST(UTPoly, binary_ops) {
	RUN_ALL_POLYS(binary_ops, "binary_ops");
}

// FIXME DCRTPoly?

//TEST(UTDCRTPoly, binary_ops) {
//	binary_ops<BigVector, ILDCRTParams, DCRTPoly>();
//}

//templet for clone_ops
template<typename Element>
void clone_ops(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint m = 8;
	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {"2","1","1","1"};
	ilv.SetValues(bbv, ilv.GetFormat());
	{
		Element ilvClone = ilv.CloneParametersOnly();

		EXPECT_EQ(ilv.GetCyclotomicOrder(), 
			  ilvClone.GetCyclotomicOrder())
			<< msg << " Failure: CloneParametersOnly GetCyclotomicOrder()";
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus())
			<< msg << " Failure: CloneParametersOnly GetModulus()";
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
			<< msg << " Failure: CloneParametersOnly GetRootOfUnity()";
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat())
			<< msg << " Failure: CloneParametersOnly GetFormat()";
	}
	{
		float stdDev = 4;
		DiscreteGaussianGeneratorImpl<VecType> dgg(stdDev);
		Element ilvClone = ilv.CloneWithNoise(dgg, ilv.GetFormat());

		EXPECT_EQ(ilv.GetCyclotomicOrder(), 
			  ilvClone.GetCyclotomicOrder())
			<< msg << " Failure: CloneWithNoise GetCyclotomicOrder()";
		EXPECT_EQ(ilv.GetModulus(), ilvClone.GetModulus())
			<< msg << " Failure: CloneWithNoise GetModulus()";
		EXPECT_EQ(ilv.GetRootOfUnity(), ilvClone.GetRootOfUnity())
			<< msg << " Failure: CloneWithNoise GetRootOfUnity()";
		EXPECT_EQ(ilv.GetFormat(), ilvClone.GetFormat())
			<< msg << " Failure: CloneWithNoise GetFormat()";
	}
}
//Instantiations of clone_ops()
TEST(UTPoly, clone_ops) {
	RUN_ALL_POLYS(clone_ops, "clone_ops");
}

//FIXME
//TEST(UTDCRTPoly, clone_ops) {
//	clone_ops<BigVector, ILDCRTParams, DCRTPoly>();
//}

//template for arithmetic_ops_element()
template<typename Element>
void arithmetic_ops_element(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint m = 8;
	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilv(ilparams);
	VecType bbv(m/2, primeModulus);
	bbv = {"2","1","4","1"};
	ilv.SetValues(bbv, ilv.GetFormat());

	typename VecType::Integer element("1");

	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"1","3","4","1"};
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n = ilvector2n.Plus(element);
		VecType expected(4, primeModulus);
		expected = {"2","3","4","1"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: Plus()";
	}
	{
		Element ilvector2n = ilv.Minus(element);
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: Minus()";
	}
	{
		typename VecType::Integer ele("2");
		Element ilvector2n = ilv.Times(ele);
		VecType expected(4, primeModulus);
		expected = {"4","2","8","2"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: Times()";
	}
	{
		Element ilvector2n(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"1","3","4","1"};
		ilvector2n.SetValues(bbv1, Format::COEFFICIENT);

		ilvector2n += element;
		VecType expected(4, primeModulus);
		expected = {"2","3","4","1"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: op+=";
	}
	{
		Element ilvector2n = ilv.Minus(element);
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: Minus()";

	}
	{
		Element ilvector2n(ilv);
		ilvector2n -= element;
		VecType expected(4, primeModulus);
		expected = {"1","0","3","0"};
		EXPECT_EQ(expected, ilvector2n.GetValues())
			<< msg << " Failure: op-=";
	}
}
//instantiations for arithmetic_ops_element()
TEST(UTPoly, arithmetic_ops_element) {
	RUN_ALL_POLYS(arithmetic_ops_element, "arithmetic_ops_element");
}

// FIXME
//TEST(UTDCRTPoly, arithmetic_ops_element) {
//	arithmetic_ops_element<BigVector, ILDCRTParams, DCRTPoly>();
//}

//template fore other_methods()
template<typename Element>
void other_methods(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	bool dbg_flag = false;
	usint m = 8;
	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	float stdDev = 4.0;
	typename Element::DggType dgg(stdDev);
	typename Element::BugType bug;
	typename Element::DugType dug;
	dug.SetModulus(primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n(ilparams);
	VecType bbv1(m/2, primeModulus);
	bbv1 = {"2","1","3","2"};
	ilvector2n.SetValues(bbv1, Format::EVALUATION);

	DEBUG("1");
	{
		Element ilv(ilvector2n);

		ilv.AddILElementOne();
		VecType expected(4, primeModulus);
		expected = {"3","2","4","3"};
		EXPECT_EQ(expected, ilv.GetValues())
			<< msg << " Failure: AddILElementOne()";
	}

	DEBUG("2");
	{
		Element ilv(ilvector2n);
		ilv = ilv.ModByTwo();
		VecType expected(4, primeModulus);
		expected = {"0","1","1","0"};
		EXPECT_EQ(expected, ilv.GetValues())
			<< msg << " Failure: ModByTwo()";
	}

	DEBUG("3");
	{
		Element ilv(ilvector2n);
		ilv.MakeSparse(2);
		VecType expected(4, primeModulus);
		expected = {"2","0","3","0"};
		EXPECT_EQ(expected, ilv.GetValues())
			<< msg << " Failure: MakeSparse(2)";

		Element ilv1(ilvector2n);
		ilv1.MakeSparse(3);
		expected = {"2","0","0","2"};

		EXPECT_EQ(expected, ilv1.GetValues())
			<< msg << " Failure: MakeSparse(3)";
	}

	DEBUG("4");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.Decompose();

		EXPECT_EQ(2U, ilv.GetLength())
			<< msg << " Failure: Decompose() length";

		EXPECT_EQ(ilv.at(0), typename Element::Integer(2))
			<< msg << " Failure: Decompose(): mismatch between original and decomposed elements at index 0.";
		
		EXPECT_EQ(ilv.at(1), typename Element::Integer(3))
			<< msg << " Failure: Decompose(): mismatch between original and decomposed elements at index 1.";
	}

	DEBUG("5");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		ilv.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv.GetModulus())
			<< msg << " Failure: SwitchFormat() ilv modulus";
		EXPECT_EQ(primitiveRootOfUnity, ilv.GetRootOfUnity())
			<< msg << " Failure: SwitchFormat() ilv rootOfUnity";
		EXPECT_EQ(Format::EVALUATION, ilv.GetFormat())
			<< msg << " Failure: SwitchFormat() ilv format";
		VecType expected(4, primeModulus);
		expected = {"69","44","65","49"};
		EXPECT_EQ(expected, ilv.GetValues())
			<< msg << " Failure: ivl.SwitchFormat() values";

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"2","1","3","2"};
		ilv1.SetValues(bbv1, Format::EVALUATION);

		ilv1.SwitchFormat();

		EXPECT_EQ(primeModulus, ilv1.GetModulus())
			<< msg << " Failure: SwitchFormat() ilv1 modulus";
		EXPECT_EQ(primitiveRootOfUnity, ilv1.GetRootOfUnity())
			<< msg << " Failure: SwitchFormat() ilv1 rootOfUnity";
		EXPECT_EQ(Format::COEFFICIENT, ilv1.GetFormat())
			<< msg << " Failure: SwitchFormat() ilv1 format";
		expected = {"2","3","50","3"};
		EXPECT_EQ(expected, ilv1.GetValues())
			<< msg << " Failure: ivl1.SwitchFormat() values";
	}
	DEBUG("6");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","1","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilvector2n1(ilparams);
		Element ilvector2n2(ilparams);
		Element ilvector2n3(ilv);
		Element ilvector2n4(dgg, ilparams);
		Element ilvector2n5(bug, ilparams);
		Element ilvector2n6(dug, ilparams);

		EXPECT_EQ(true, ilvector2n1.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n1";
		EXPECT_EQ(true, ilvector2n2.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n2";
		EXPECT_EQ(false, ilvector2n3.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n3";
		EXPECT_EQ(false, ilvector2n4.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n4";
		EXPECT_EQ(false, ilvector2n5.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n5";
		EXPECT_EQ(false, ilvector2n6.IsEmpty())
			<< msg << " Failure: DestroyPreComputedSamples() 2n6";
	}

	DEBUG("7");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv ={"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		typename VecType::Integer modulus("17");
		typename VecType::Integer rootOfUnity("15");

		ilv.SwitchModulus(modulus, rootOfUnity);
		VecType expected(4, modulus);
		expected = {"0","1","15","2"};
		EXPECT_EQ(expected, ilv.GetValues())
			<< msg << " Failure: SwitchModulus()";

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 ={"56","43","35","28"};
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		typename VecType::Integer modulus1("193");
		typename VecType::Integer rootOfUnity1("150");

		ilv1.SwitchModulus(modulus1, rootOfUnity1);
		VecType expected2(4, modulus1);
		expected2 = {"176","163","35","28"};
		EXPECT_EQ(expected2, ilv1.GetValues())
			<< msg << " Failure: SwitchModulus()";
	}

	DEBUG("8");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"2","4","3","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"2","0","3","2"};
		ilv1.SetValues(bbv1, Format::COEFFICIENT);

		Element ilv2(ilparams);
		VecType bbv2(m/2, primeModulus);
		bbv2 = {"2","1","3","2"};
		ilv2.SetValues(bbv2, Format::COEFFICIENT);

		EXPECT_EQ(true, ilv.InverseExists())
			<< msg << " Failure: ilv.InverseExists()";
		EXPECT_EQ(false, ilv1.InverseExists())
			<< msg << " Failure: ilv1.InverseExists()";
		EXPECT_EQ(true, ilv2.InverseExists())
			<< msg << " Failure: ilv2.InverseExists()";
	}

	DEBUG("9");
	{
		Element ilv1(ilparams);
		VecType bbv1(m/2, primeModulus);
		bbv1 = {"2","4","3","2"};
		ilv1.SetValues(bbv1, Format::EVALUATION);

		Element ilvInverse1 = ilv1.MultiplicativeInverse();
		Element ilvProduct1 = ilv1 * ilvInverse1;

		for (usint i = 0; i < m/2; ++i)
		{
			EXPECT_EQ(ilvProduct1.at(i), typename Element::Integer(1))
				<< msg << " Failure: ilvProduct1.MultiplicativeInverse() @ index "<<i;
		}
	}

	DEBUG("A");
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","1"};
		ilv.SetValues(bbv, Format::COEFFICIENT);
		
		EXPECT_EQ(36, ilv.Norm()) << msg << " Failure: Norm()";
	}
	DEBUG("B");	
	{
		Element ilv(ilparams);
		VecType bbv(m/2, primeModulus);
		bbv = {"56","1","37","2"};
		ilv.SetValues(bbv, Format::COEFFICIENT);

		usint index = 3;
		Element ilvAuto(ilv.AutomorphismTransform(index));
		VecType expected(4, primeModulus);
		expected = {"56","2","36","1"};
		EXPECT_EQ(expected, ilvAuto.GetValues())
			<< msg << " Failure: AutomorphismTransform()";
	}
}
//Instantiations of other_methods()
TEST(UTPoly, other_methods) {
	RUN_ALL_POLYS(other_methods, "other_methods");
}

// FIXME
//TEST(UTDCRTPoly, other_methods) {
//	other_methods<BigVector, ILDCRTParams, DCRTPoly>();
//}

template<typename Element>
void cyclotomicOrder_test(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint m = 8;
	shared_ptr<ParmType> ilparams0( new ParmType(m, typename VecType::Integer("1234"), typename VecType::Integer("5678")) );
	Element ilv0(ilparams0);
	EXPECT_EQ(ilparams0->GetCyclotomicOrder(), ilv0.GetCyclotomicOrder())
		<< msg << " Failure: GetCyclotomicOrder()";
}

//Instantiations of cyclotomicOrder_test()
TEST(UTPoly, cyclotomicOrder_test) {
	RUN_ALL_POLYS(cyclotomicOrder_test, "cyclotomicOrder_test");
}

TEST(UTDCRTPoly, cyclotomicOrder_test) {
	RUN_BIG_DCRTPOLYS(cyclotomicOrder_test, "cyclotomicOrder_test");
}

template<typename Element>
void constructors_test(const string& msg) {

	bool dbg_flag = false;
	usint m = 8;
	usint towersize = 3;

	std::vector<NativeInteger> moduli(towersize);
	moduli = {NativeInteger("8353"), NativeInteger("8369"), NativeInteger("8513")};
	std::vector<NativeInteger> rootsOfUnity(towersize);
	rootsOfUnity = {NativeInteger("8163"), NativeInteger("6677"), NativeInteger("156")};

	typename Element::Integer modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
	}

	shared_ptr<ILNativeParams> ilparams0( new ILNativeParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<ILNativeParams> ilparams1( new ILNativeParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<ILNativeParams> ilparams2( new ILNativeParams(m, moduli[2], rootsOfUnity[2]) );

	NativePoly ilv0(ilparams0);
	NativeVector bbv0(m/2, moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	NativePoly ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	NativePoly ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<typename Element::Integer>> ildcrtparams( new ILDCRTParams<typename Element::Integer>(m, moduli, rootsOfUnity) );

	std::vector<NativePoly> ilvector2nVector;
	ilvector2nVector.push_back(ilv0);
	ilvector2nVector.push_back(ilv1);
	ilvector2nVector.push_back(ilv2);

	DEBUG("1");
	float stdDev = 4.0;
	typename Element::DggType dgg(stdDev);

	{
		Element ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) 
			<< msg << " Failure: ildcrtparams ctor ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<< msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<< msg << " Failure: ildcrtparams ctor ilva.GetModulus()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())			
			<< msg << " Failure: ildcrtparams ctor ilva.GetNumOfElements()";
	}

	DEBUG("2");
	{
		Element ilva(ilvector2nVector);

		DEBUG("2.0");
		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())			
			<< msg << " Failure: ctor ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<< msg << " Failure: ctor ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<< msg << " Failure: ctor ilva.GetCyclotomicOrder()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
			<< msg << " Failure: ctor ilva.GetNumOfElements()";

		DEBUG("2.1");
		std::vector<NativePoly> ilvector2nVectorInconsistent(towersize);
		shared_ptr<ILNativeParams> ilparamsNegativeTestCase( new ILNativeParams(128, NativeInteger("1231"), NativeInteger("213")) );
		NativePoly ilvNegative(ilparamsNegativeTestCase);
		ilvector2nVectorInconsistent[0] = ilvNegative;
		ilvector2nVectorInconsistent[1] = ilv1;
		ilvector2nVectorInconsistent[2] = ilv2;

		DEBUG("2.2");
		for( size_t ii=0; ii<ilvector2nVectorInconsistent.size(); ii++ ) {
			DEBUG(ii << " item " << ilvector2nVectorInconsistent.at(ii).GetParams().use_count());			

		}
		EXPECT_THROW(testDCRTPolyConstructorNegative(ilvector2nVectorInconsistent), std::logic_error)
			<< msg << " Failure: ilvector2nVectorInconsistent";
	}

	DEBUG("4");
	{
		Element ilva0;
		Element ilva1(ildcrtparams);
		Element ilva2(ilvector2nVector);

		std::vector<Element> ilvaVector( { ilva0, ilva1, ilva2 } );

		//copy constructor
		Element ilva0Copy(ilva0);
		Element ilva1Copy(ilva1);
		Element ilva2Copy(ilva2);

		std::vector<Element> ilvaCopyVector( { ilva0Copy, ilva1Copy, ilva2Copy } );

		for (usint i = 0; i < 3; ++i)
		{
			EXPECT_EQ(ilvaVector[i].GetFormat(), ilvaCopyVector[i].GetFormat())
				<< msg << " Failure: ctor ilvaCopyVector["<<i<<"].GetFormat()";
			EXPECT_EQ(ilvaVector[i].GetModulus(), ilvaCopyVector[i].GetModulus())
				<< msg << " Failure: ctor ilvaCopyVector["<<i<<"].GetModulus()";
			EXPECT_EQ(ilvaVector[i].GetCyclotomicOrder(), ilvaCopyVector[i].GetCyclotomicOrder())
				<< msg << " Failure: ctor ilvaCopyVector["<<i<<"].GetCyclotomicOrder()";
			EXPECT_EQ(ilvaVector[i].GetNumOfElements(), ilvaCopyVector[i].GetNumOfElements())
				<< msg << " Failure: ctor ilvaCopyVector["<<i<<"].GetNumOfElements()";
			if(i==0 || i==1) // to ensure that GetElementAtIndex is not called on uninitialized DCRTPoly objects.
				continue;
			for (usint j = 0; j < towersize; ++j)
			{
				EXPECT_EQ(ilvaVector[i].GetElementAtIndex(j), ilvaCopyVector[i].GetElementAtIndex(j))
					<< msg << " Failure: ctor ilvaCopyVector["<<i<<"].GetElementAtIndex("<<j<<")";
			}
		}

	}

	DEBUG("5");
	{
		DEBUG("ild mod " << ildcrtparams->GetModulus());
		Element ilva(dgg, ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())			
			<< msg << " Failure: ctor(dgg, ldcrtparams) ilva.GetFormat()";
		EXPECT_EQ(modulus, ilva.GetModulus())
			<< msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetModulus()";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
			<< msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetCyclotomicOrder()";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
			<< msg << " Failure: ctor(dgg, ildcrtparams) ilva.GetNumOfElements()";
	}

	DEBUG("6");
	{
		Element ilva(dgg, ildcrtparams);
		Element ilvaClone(ilva.CloneParametersOnly());

		std::vector<NativePoly> towersInClone = ilvaClone.GetAllElements();

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat()) << msg << "Failure: clone parameters format mismatch";
		EXPECT_EQ(ilva.GetParams(), ilvaClone.GetParams()) << msg << "Failure: clone parameters parameter mismatch";
		EXPECT_EQ(towersInClone.size(), ilva.GetAllElements().size()) << msg << "Failure: clone parameters towers size mismatch";
	}

}

TEST(UTDCRTPoly, constructors_test) {
	RUN_BIG_DCRTPOLYS(constructors_test, "constructors_test");
}

// Signed mod must handle the modulo operation for both positive and negative numbers
// It is used in decoding/decryption of homomorphic encryption schemes
template<typename Element>
void signed_mod_tests(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint m = 8;

	typename VecType::Integer primeModulus("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams( new ParmType(m, primeModulus, primitiveRootOfUnity) );

	Element ilvector2n1(ilparams,COEFFICIENT);
	VecType bbv1(m / 2, primeModulus);
	bbv1 = {"62","7","65","8"};
	ilvector2n1.SetValues(bbv1, ilvector2n1.GetFormat());

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.Mod(2);
		VecType expected(4, primeModulus);
		expected = {"1","1","0","0"};
		EXPECT_EQ(expected, ilv1.GetValues())
			<< msg << " Failure: ilv1.Mod(TWO)";
	}

	{
		Element ilv1(ilparams, COEFFICIENT);
		ilv1 = ilvector2n1.Mod(5);
		VecType expected(4, primeModulus);
		expected = {"4","2","2","3"};
		EXPECT_EQ(expected, ilv1.GetValues())
			<< msg << " Failure: ilv1.Mod(FIVE)";
	}
}
//Instantiations of signed_mod_tests()
TEST(UTPoly, signed_mod_tests) {
	RUN_ALL_POLYS(signed_mod_tests, "signed_mod_tests");
}

// FIXME
//TEST(UTDCRTPoly, signed_mod_tests) {
//	signed_mod_tests<BigVector, ILDCRTParams, DCRTPoly>();
//}

template<typename Element>
void transposition_test(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

  bool dbg_flag = false;
	usint m = 8;

	typename VecType::Integer q("73");
	typename VecType::Integer primitiveRootOfUnity("22");

	shared_ptr<ParmType> ilparams(new ParmType(m, q, primitiveRootOfUnity));

	Element ilvector2n1(ilparams, COEFFICIENT);
	ilvector2n1 = {"31","21","15","34"};

	// converts to evaluation representation
	ilvector2n1.SwitchFormat();
	DEBUG("ilvector2n1 a "<<ilvector2n1);

	ilvector2n1 = ilvector2n1.Transpose();
	DEBUG("ilvector2n1 b "<<ilvector2n1);

	// converts back to coefficient representation
	ilvector2n1.SwitchFormat();

	DEBUG("ilvector2n1 c "<<ilvector2n1);

	Element ilvector2n2(ilparams);

	VecType bbv0(m / 2, q);
	bbv0 = {"31","39","58","52"};
	ilvector2n2.SetValues(bbv0, Format::COEFFICIENT);

	DEBUG("ilvector2n2 a "<<ilvector2n2);

	EXPECT_EQ(ilvector2n2, ilvector2n1)
		<< msg << " Failure: transposition test";
}
//Instantiations of transposition_test()
TEST(UTPoly, transposition_test) {
	RUN_ALL_POLYS(transposition_test, "transposition_test");
}
// FIXME DCRT?

template<typename Element>
void getters_and_operators(const string& msg) {
	usint m = 8;
	usint towersize = 3;

	std::vector<NativeInteger> moduli(towersize);
	moduli = {NativeInteger("8353"),
		  NativeInteger("8369"),
 		  NativeInteger("8513")};

	std::vector<NativeInteger> rootsOfUnity(towersize);

	rootsOfUnity = {NativeInteger("8163"), 
			NativeInteger("6677"), 
			NativeInteger("156")};

	typename Element::Integer modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
	}

	shared_ptr<ILNativeParams> ilparams0( new ILNativeParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<ILNativeParams> ilparams1( new ILNativeParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<ILNativeParams> ilparams2( new ILNativeParams(m, moduli[2], rootsOfUnity[2]) );

	NativePoly ilv0(ilparams0);
	NativeVector bbv0(ilparams0->GetRingDimension(), moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	NativePoly ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	NativePoly ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<typename Element::Integer>> ildcrtparams( new ILDCRTParams<typename Element::Integer>(m, moduli, rootsOfUnity) );

	std::vector<NativePoly> ilvector2nVector(towersize);

	ilvector2nVector = {ilv0, ilv1, ilv2};	
	{
		Element ilva(ildcrtparams);

		EXPECT_EQ(Format::EVALUATION, ilva.GetFormat())
		  << msg << " Failure: ilva format";
		EXPECT_EQ(modulus, ilva.GetModulus())
		  << msg << " Failure: ilva modulus";
		EXPECT_EQ(m, ilva.GetCyclotomicOrder())
		  << msg << " Failure: ilva cyclotomicOrder";
		EXPECT_EQ(towersize, ilva.GetNumOfElements())
		  << msg << " Failure: ilva number of elements";
	}

	Element ilva(ilvector2nVector);

	{
		Element ilva1(ilva);
		EXPECT_TRUE(ilva == ilva1) << msg << " Failure: ilva CTOR";
	}

	{
		Element ilva1 = ilva;
		EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva operator=";
	}

	{
		Element ilva1(ildcrtparams);
		ilva1 = {2, 4, 3, 2};
		EXPECT_EQ(ilva, ilva1) << msg << " Failure: ilva CTOR(params)";
	}

	{
		NativePoly ilvect0(ilparams0);
		NativeVector bbv1(m/2, moduli[0]);
		bbv1 = {"2","1","3","2"};
		ilvect0.SetValues(bbv1, Format::EVALUATION);

		NativePoly ilvect1(ilvect0);
		ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

		NativePoly ilvect2(ilvect0);
		ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<NativePoly> ilvector2nVector1(towersize);
		ilvector2nVector1 = {ilvect0, ilvect1, ilvect2};

		Element ilva1(ilvector2nVector1);

		EXPECT_TRUE(ilva!=ilva1) << msg << " Failure: ilva operator!=";
	}

}

TEST(UTDCRTPoly, getters_and_operators) {
	RUN_BIG_DCRTPOLYS(getters_and_operators, "getters_and_operators");
}

template<typename Element>
void arithmetic_ops_element_2(const string& msg) {
	usint m = 8;
	usint towersize = 3;

	std::vector<NativeInteger> moduli(towersize);
	moduli = {
		NativeInteger("8353"), 
		NativeInteger("8369"), 
		NativeInteger("8513")
	};
	std::vector<NativeInteger> rootsOfUnity(towersize);
	rootsOfUnity = {
		NativeInteger("8163"), 
		NativeInteger("6677"), 
		NativeInteger("156")};

	typename Element::Integer modulus(1);
	for (usint i = 0; i < towersize; ++i)
	{
		modulus = modulus * typename Element::Integer(moduli[i].ConvertToInt());
	}

	shared_ptr<ILNativeParams> ilparams0( new ILNativeParams(m, moduli[0], rootsOfUnity[0]) );
	shared_ptr<ILNativeParams> ilparams1( new ILNativeParams(m, moduli[1], rootsOfUnity[1]) );
	shared_ptr<ILNativeParams> ilparams2( new ILNativeParams(m, moduli[2], rootsOfUnity[2]) );

	NativePoly ilv0(ilparams0);
	NativeVector bbv0(m/2, moduli[0]);
	bbv0 = {"2","4","3","2"};
	ilv0.SetValues(bbv0, Format::EVALUATION);

	NativePoly ilv1(ilv0);
	ilv1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	NativePoly ilv2(ilv0);
	ilv2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	shared_ptr<ILDCRTParams<typename Element::Integer>> ildcrtparams( new ILDCRTParams<typename Element::Integer>(m, moduli, rootsOfUnity) );

	std::vector<NativePoly> ilvector2nVector(towersize);
	ilvector2nVector[0] = ilv0;
	ilvector2nVector[1] = ilv1;
	ilvector2nVector[2] = ilv2;

	Element ilva(ilvector2nVector);

	NativePoly ilvect0(ilparams0);
	NativeVector bbv1(m/2, moduli[0]);
	bbv1 = {"2","1","2","0"};
	ilvect0.SetValues(bbv1, Format::EVALUATION);

	NativePoly ilvect1(ilvect0);
	ilvect1.SwitchModulus(moduli[1], rootsOfUnity[1]);

	NativePoly ilvect2(ilvect0);
	ilvect2.SwitchModulus(moduli[2], rootsOfUnity[2]);

	std::vector<NativePoly> ilvector2nVector1(towersize);
	ilvector2nVector1[0] = ilvect0;
	ilvector2nVector1[1] = ilvect1;
	ilvector2nVector1[2] = ilvect2;

	Element ilva1(ilvector2nVector1);

	// Plus method
	{
		Element ilvaCopy(ilva.Plus(ilva1));

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"4","5","5","2"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Plus()";
		}
	}

	// operator+ (which is ModAdd)
	{
		Element ilvaCopy(ilva + ilva1);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"4","5","5","2"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: +";
		}
	}

	// += (which is ModAddEq)
	{
		Element ilvaCopy(ilva);
		ilvaCopy += ilva1;

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"4","5","5","2"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: +=";
		}
	}

	{
		Element ilvaCopy(ilva.Minus(ilva1));
		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"0","3","1","2"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Minus";
		}
	}
	{
		Element ilvaResult(ilva);
		ilvaResult -= ilva1;
		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaResult.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"0","3","1","2"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: -=";
		}
	}
	{
		Element ilvaResult(ilva.Times(ilva1));
		for (usint i = 0; i < ilvaResult.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaResult.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"4","4","6","0"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: Times()";
		}
	}
	{
		Element ilvaCopy(ilva);
		ilvaCopy.AddILElementOne();

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"3","5","4","3"};
			EXPECT_EQ(expected, ilv.GetValues()) << msg << " Failure: AddILElementOne";
		}
	}

	{
		Element ilvaInv(ilva.MultiplicativeInverse());

		NativePoly ilvectInv0 = ilvaInv.GetElementAtIndex(0);
		//TODO: SHOULD BE ABLE TO SAY NativePoly ilvectInv0 = ilvaInv[0];
		NativePoly ilvectInv1 = ilvaInv.GetElementAtIndex(1);
		NativePoly ilvectInv2 = ilvaInv.GetElementAtIndex(2);
		NativeVector expected0 (4, ilvectInv0.GetModulus());
		expected0 = {"4177","6265","5569","4177"};
		EXPECT_EQ(expected0, ilvectInv0.GetValues())
		  << msg << " Failure: ilvectInv0 MultiplicativeInverse()";
		EXPECT_EQ(NativeInteger("8353"), ilvectInv0.GetModulus())
		  << msg << " Failure: ilvectInv0 MultiplicativeInverse() modulus";
		EXPECT_EQ(NativeInteger("8163"), ilvectInv0.GetRootOfUnity())
		  << msg << " Failure: ilvectInv0 MultiplicativeInverse() rootOfUnity";

		NativeVector expected1 (4, ilvectInv1.GetModulus());
		expected1 = {"4185","6277","2790","4185"};
		EXPECT_EQ(expected1, ilvectInv1.GetValues())
		  << msg << " Failure: ilvectInv1 MultiplicativeInverse()";
		EXPECT_EQ(NativeInteger("8369"), ilvectInv1.GetModulus())
		  << msg << " Failure: ilvectInv1 MultiplicativeInverse() modulus";
		EXPECT_EQ(NativeInteger("6677"), ilvectInv1.GetRootOfUnity())
		  << msg << " Failure: ilvectInv1 MultiplicativeInverse() rootOfUnity";

		NativeVector expected2 (4, ilvectInv2.GetModulus());
		expected2 = {"4257","6385","2838","4257"};
		EXPECT_EQ(expected2, ilvectInv2.GetValues())
		  << msg << " Failure: ilvectInv2 MultiplicativeInverse()";
		EXPECT_EQ(NativeInteger("8513"), ilvectInv2.GetModulus())
		  << msg << " Failure: ilvectInv2 MultiplicativeInverse() modulus";
		EXPECT_EQ(NativeInteger("156"), ilvectInv2.GetRootOfUnity())
		  << msg << " Failure: ilvectInv2 MultiplicativeInverse() rootOfUnity";
		EXPECT_THROW(ilva1.MultiplicativeInverse(), std::logic_error)      
			<< msg << " Failure: throw MultiplicativeInverse()";
	}

	{
		Element ilvaCopy(ilva);

		ilvaCopy.MakeSparse(2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);

			EXPECT_EQ(NativeInteger(0), ilv.at(1))
				<< msg << " Failure MakeSparse() index 1";
			EXPECT_EQ(NativeInteger(0), ilv.at(3))
				<< msg << " Failure MakeSparse() index 3";
		}
	}

	{
	    EXPECT_TRUE(ilva.InverseExists()) << msg << " Failure: ilva.InverseExists()";
		EXPECT_FALSE(ilva1.InverseExists()) << msg << " Failure: ilva1.InverseExists()";
	}

	// this case is NOT used because SwitchModulus is not really defined for an DCRTPoly, so...
	if( false )
	{
		NativePoly ilvS0(ilparams0);
		NativeVector bbvS0(m/2, moduli[0]);
		bbvS0 = {"23462","467986","33863","2113"};
		ilvS0.SetValues(bbvS0, Format::EVALUATION);

		NativePoly ilvS1(ilvS0);
		NativePoly ilvS2(ilvS0);

		ilvS0.SwitchModulus(moduli[0], rootsOfUnity[0]);
		ilvS1.SwitchModulus(moduli[1], rootsOfUnity[1]);
		ilvS2.SwitchModulus(moduli[2], rootsOfUnity[2]);

		std::vector<NativePoly> ilvector2nVectorS(towersize);
		ilvector2nVectorS[0] = ilvS0;
		ilvector2nVectorS[1] = ilvS1;
		ilvector2nVectorS[2] = ilvS2;

		Element ilvaS(ilvector2nVectorS);
		typename Element::Integer modulus2("113");
		typename Element::Integer rootOfUnity2(lbcrypto::RootOfUnity<typename Element::Integer>(m, modulus2));

		ilvaS.SwitchModulus(modulus2, rootOfUnity2);

		NativePoly ilvectS0 = ilvaS.GetElementAtIndex(0);
		NativePoly ilvectS1 = ilvaS.GetElementAtIndex(1);
		NativePoly ilvectS2 = ilvaS.GetElementAtIndex(2);

		EXPECT_EQ(NativeInteger("80"), ilvectS0.at(0));
		EXPECT_EQ(NativeInteger("62"), ilvectS0.at(1));
		EXPECT_EQ(NativeInteger("85"), ilvectS0.at(2));
		EXPECT_EQ(NativeInteger("79"), ilvectS0.at(3));
		EXPECT_EQ(NativeInteger("113"), ilvectS0.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS0.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(NativeInteger("66"), ilvectS1.at(0));
		EXPECT_EQ(NativeInteger("16"), ilvectS1.at(1));
		EXPECT_EQ(NativeInteger("64"), ilvectS1.at(2));
		EXPECT_EQ(NativeInteger("79"), ilvectS1.at(3));
		EXPECT_EQ(NativeInteger("113"), ilvectS1.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS1.GetRootOfUnity().ConvertToInt());

		EXPECT_EQ(NativeInteger(4), ilvectS2.at(0));
		EXPECT_EQ(NativeInteger("44"), ilvectS2.at(1));
		EXPECT_EQ(NativeInteger("84"), ilvectS2.at(2));
		EXPECT_EQ(NativeInteger("79"), ilvectS2.at(3));
		EXPECT_EQ(NativeInteger("113"), ilvectS2.GetModulus());
		EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilvectS2.GetRootOfUnity().ConvertToInt());
	}

	{
		Element ilvaCopy(ilva);
		typename Element::Integer modulus2("113");
		typename Element::Integer rootOfUnity2(lbcrypto::RootOfUnity<typename Element::Integer>(m, modulus2));
		ilvaCopy.SwitchModulusAtIndex(0, modulus2, rootOfUnity2);

		for (usint i = 0; i < ilvaCopy.GetNumOfElements(); ++i)
		{
			NativePoly ilv = ilvaCopy.GetElementAtIndex(i);
			NativeVector expected (4, ilv.GetModulus());
			expected = {"2","4","3","2"};
			EXPECT_EQ(expected, ilv.GetValues())
				<< msg << " Failure: ilv.SwitchModulusAtIndex";

			if(i==0){
				EXPECT_EQ(modulus2.ConvertToInt(), ilv.GetModulus().ConvertToInt())
					<< msg << " Failure: SwitchModulusAtIndex modulus";
				EXPECT_EQ(rootOfUnity2.ConvertToInt(), ilv.GetRootOfUnity().ConvertToInt())	
				<< msg << " Failure: SwitchModulusAtIndex rootOfUnity";
			}
		}
	}

}

TEST(UTDCRTPoly, arithmetic_ops_element_2) {
	RUN_BIG_DCRTPOLYS(arithmetic_ops_element_2, "arithmetic_ops_element_2");
}

template<typename Element>
void decompose_test(const string& msg) {
	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;

	float stdDev = 4;
	typename Element::DggType dgg(stdDev);

	shared_ptr<ILDCRTParams<typename Element::Integer>> params = GenerateDCRTParams<typename Element::Integer>(order, towersize, nBits);
	Element DCRTPolyFirst(dgg, params, Format::COEFFICIENT);

	Element DCRTPolyOriginal(DCRTPolyFirst);
	DCRTPolyFirst.Decompose();

	EXPECT_EQ(DCRTPolyOriginal.GetNumOfElements(), DCRTPolyFirst.GetNumOfElements())
		<< msg << " Failure DCRTPoly.Decompose(): Mismatch in the number of towers";

	for(usint i=0; i<DCRTPolyFirst.GetNumOfElements(); i++) {
		NativePoly ilTowerOriginal(DCRTPolyOriginal.GetElementAtIndex(i));
		NativePoly ilTowerDecomposed(DCRTPolyFirst.GetElementAtIndex(i));

		EXPECT_EQ(ilTowerDecomposed.GetLength(), ilTowerOriginal.GetLength()/2)
			<< msg << " Failure: DCRTPoly.Decompose(): ilVector2n element "<<i<<" in DCRTPoly is not half the length";

		for(usint j=0; j<ilTowerDecomposed.GetLength(); j++) {
			EXPECT_EQ(ilTowerDecomposed.at(j), ilTowerOriginal.at(2*j))
				<< msg << " Failure: DCRTPoly.Decompose(): Value mismatch";
		}
	}

}

TEST(UTDCRTPoly, decompose_test) {
	RUN_BIG_DCRTPOLYS(decompose_test, "decompose_test");
}

template<typename Element>
void mod__ops_on_two_Polys(const string& msg) {

	using VecType = typename Element::Vector;
	using ParmType = typename Element::Params;

	usint order = 8;
	usint nBits = 7;

	typename VecType::Integer primeModulus = lbcrypto::FirstPrime<typename VecType::Integer>(nBits, order);
	typename VecType::Integer primitiveRootOfUnity = lbcrypto::RootOfUnity<typename VecType::Integer>(order, primeModulus);

	shared_ptr<ParmType> ilparams( new ParmType(order, primeModulus, primitiveRootOfUnity) );

	typename Element::DugType distrUniGen = typename Element::DugType();
	distrUniGen.SetModulus(primeModulus);

	Element ilv1(distrUniGen, ilparams);
	VecType bbv1 (ilv1.GetValues());

	Element ilv2(distrUniGen, ilparams);
	VecType bbv2(ilv2.GetValues());

	{
		Element ilvResult = ilv1 + ilv2;
		VecType bbvResult(ilvResult.GetValues());

		for (usint i=0; i<order/2; i++) {
			EXPECT_EQ(bbvResult.at(i), (bbv1.at(i) + bbv2.at(i)).Mod(primeModulus)) << msg << " Poly + operation returns incorrect results.";
		}
	}

	{
		Element ilvResult = ilv1 * ilv2;
		VecType bbvResult(ilvResult.GetValues());

		for (usint i=0; i<order/2; i++) {
			EXPECT_EQ(bbvResult.at(i), (bbv1.at(i) * bbv2.at(i)).Mod(primeModulus)) << msg << " Poly * operation returns incorrect results.";
		}
	}

}

TEST(UTPoly, mod__ops_on_two_Polys) {
	RUN_ALL_POLYS(mod__ops_on_two_Polys, "mod__ops_on_two_Polys");
}

template<typename Element>
void mod__ops_on_two_DCRTPolys(const string& msg) {

	usint order = 16;
	usint nBits = 24;
	usint towersize = 3;

	shared_ptr<ILDCRTParams<typename Element::Integer>> ildcrtparams = GenerateDCRTParams<typename Element::Integer>(order, towersize, nBits);

	typename Element::DugType dug;

	Element op1(dug, ildcrtparams);
	Element op2(dug, ildcrtparams);

	{
		Element sum = op1 + op2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<ildcrtparams->GetRingDimension(); j++) {
				NativeInteger actualResult(sum.GetElementAtIndex(i).at(j));
				NativeInteger expectedResult((op1.GetElementAtIndex(i).at(j) + op2.GetElementAtIndex(i).at(j)).Mod(ildcrtparams->GetParams()[i]->GetModulus()));
				EXPECT_EQ(actualResult, expectedResult) << msg << " Failure: DCRTPoly + operation tower "<<i<<" index "<<j;
			}
		}
	}

	{
		Element prod = op1 * op2;

		for(usint i=0; i<towersize; i++) {
			for(usint j=0; j<ildcrtparams->GetRingDimension(); j++) {
				NativeInteger actualResult(prod.GetElementAtIndex(i).at(j));
				NativeInteger expectedResult((op1.GetElementAtIndex(i).at(j) * op2.GetElementAtIndex(i).at(j)).Mod(ildcrtparams->GetParams()[i]->GetModulus()));
				EXPECT_EQ(actualResult, expectedResult)  << msg << " Failure: DCRTPoly * operation tower "<<i<<" index "<<j;
			}
		}
	}

}

TEST(UTDCRTPoly, mod__ops_on_two_DCRTPolys) {
	RUN_BIG_DCRTPOLYS(mod__ops_on_two_DCRTPolys, "mod__ops_on_two_DCRTPolys");
}

// only need to try this with one
void testDCRTPolyConstructorNegative(std::vector<NativePoly> &towers) {
	DCRTPoly expectException(towers);
}
