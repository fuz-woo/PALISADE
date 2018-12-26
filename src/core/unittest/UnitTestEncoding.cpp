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
  This code exercises the encoding libraries of the PALISADE lattice encryption library.
*/

#define PROFILE
#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "encoding/encodings.h"

#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "lattice/elemparamfactory.h"

using namespace std;
using namespace lbcrypto;


class UTEncoding : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST_F(UTEncoding,scalar_encoding) {
	vector<int64_t> valuev;
	usint m = 8;
	vector<PlaintextModulus> ptmv( {128, PlaintextModulus(1)<<25, PlaintextModulus(1)<<40, PlaintextModulus(1)<<60} );
	for( auto& ptm : ptmv )
		valuev.push_back( ptm / 8 * 3 - 1 );

	// try for small and large
	for( size_t i=0; i<valuev.size(); i++ ) {
		auto value = valuev[i];
		auto ptm = ptmv[i];

		shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
		EncodingParams ep( new EncodingParamsImpl( ptm ) );

		ScalarEncoding	se(lp, ep, value);
		se.Encode();
		EXPECT_EQ( se.GetElement<Poly>()[0].ConvertToInt(), (uint64_t)value ) << "encoding #" << i << ":" << value << " failed";
		EXPECT_EQ( se.GetElement<Poly>()[1].ConvertToInt(), (uint64_t)0 ) << "encoding 0 failed";

		se.Decode();
		EXPECT_EQ( se.GetScalarValue(), value ) << "positive #" << i << " scalar failed";

		ScalarEncoding	se2(lp, ep, -value);
		se2.Encode();
		se2.Decode();
		EXPECT_EQ( se2.GetScalarValue(), -value ) << "negative #" << i << " scalar failed";

		ScalarEncoding	se3(lp, ep, (ptm/2)+1);
		EXPECT_THROW( se3.Encode(), config_error ) << "Encode did not throw the proper exception";

		ScalarEncoding	se3n(lp, ep, ((-1*(int64_t)ptm)/2));
		EXPECT_THROW( se3n.Encode(), config_error ) << "Encode did not throw the proper exception";

		ScalarEncoding	se4(lp, ep, ptm/2);
		se4.Encode();
		se4.Decode();
		EXPECT_EQ( se4.GetScalarValue(), (int64_t)ptm/2 ) << "largest number";

		ScalarEncoding	se5(lp, ep, (-1*(int64_t)ptm)/2 + 1);
		se5.Encode();
		se5.Decode();
		EXPECT_EQ( se5.GetScalarValue(), (-1*(int64_t)ptm)/2 + 1 ) << "smallest number";
	}
}

TEST_F(UTEncoding,coef_packed_encoding) {
	vector<int64_t> value = {32, 17, 8, -12, -32, 22, -101, 6 };
	usint m = 16;

	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
	EncodingParams ep( new EncodingParamsImpl(256) );

	CoefPackedEncoding	se(lp, ep, value);
	se.Encode();
	se.Decode();
	se.SetLength( value.size() );
	EXPECT_EQ( se.GetCoefPackedValue(), value ) << "CoefPacked";
}

TEST_F(UTEncoding,packed_int_ptxt_encoding) {
	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	shared_ptr<ILParams> lp(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
	EncodingParams ep(new EncodingParamsImpl(p,8));

	PackedEncoding::SetParams(m, ep);

	std::vector<int64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedEncoding	se(lp, ep, vectorOfInts1);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int";
}

TEST_F(UTEncoding,packed_int_ptxt_encoding_negative) {
	usint m = 22;
	PlaintextModulus p = 89;
	BigInteger modulusQ("955263939794561");
	BigInteger squareRootOfRoot("941018665059848");
	BigInteger bigmodulus("80899135611688102162227204937217");
	BigInteger bigroot("77936753846653065954043047918387");

	auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
	ChineseRemainderTransformArb<BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	shared_ptr<ILParams> lp(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
	EncodingParams ep(new EncodingParamsImpl(p,8));

	PackedEncoding::SetParams(m, ep);

	std::vector<int64_t> vectorOfInts1 = { 1,2,-3,4,5,-6,7,8,0,0 };
	PackedEncoding	se(lp, ep, vectorOfInts1);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int";
}

TEST_F(UTEncoding,packed_int_ptxt_encoding_DCRTPoly_prime_cyclotomics) {

	usint init_size = 3;
	usint dcrtBits = 24;
	usint dcrtBitsBig = 58;

	usint m = 1811;

	PlaintextModulus p = 2 * m + 1;
	BigInteger modulusP(p);

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	EncodingParams ep(new EncodingParamsImpl(p));

	PackedEncoding::SetParams(m, ep);

	std::vector<int64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedEncoding	se(paramsDCRT, ep, vectorOfInts1);

	se.Encode();

	se.GetElement<DCRTPoly>().SwitchFormat();
	se.GetElement<DCRTPoly>().SwitchFormat();

	se.Decode();

	se.SetLength(vectorOfInts1.size());

	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int - prime cyclotomics";

}

TEST_F(UTEncoding,packed_int_ptxt_encoding_DCRTPoly_prime_cyclotomics_negative) {

	usint init_size = 3;
	usint dcrtBits = 24;
	usint dcrtBitsBig = 58;

	usint m = 1811;

	PlaintextModulus p = 2 * m + 1;
	BigInteger modulusP(p);

	usint mArb = 2 * m;
	usint mNTT = pow(2, ceil(log2(2 * m - 1)));

	// populate the towers for the small modulus

	vector<NativeInteger> init_moduli(init_size);
	vector<NativeInteger> init_rootsOfUnity(init_size);

	NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, mArb);
	init_moduli[0] = q;
	init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mArb);
		init_moduli[i] = q;
		init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
	}

	// populate the towers for the big modulus

	vector<NativeInteger> init_moduli_NTT(init_size);
	vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

	q = FirstPrime<NativeInteger>(dcrtBitsBig, mNTT);
	init_moduli_NTT[0] = q;
	init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

	for (usint i = 1; i < init_size; i++) {
		q = lbcrypto::NextPrime(q, mNTT);
		init_moduli_NTT[i] = q;
		init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
	}

	shared_ptr<ILDCRTParams<BigInteger>> paramsDCRT(new ILDCRTParams<BigInteger>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT, init_rootsOfUnity_NTT));

	EncodingParams ep(new EncodingParamsImpl(p));

	PackedEncoding::SetParams(m, ep);

	std::vector<int64_t> vectorOfInts1 = { 1,2,-3,4,5,6,-7,8,0,0 };
	PackedEncoding	se(paramsDCRT, ep, vectorOfInts1);

	se.Encode();

	se.GetElement<DCRTPoly>().SwitchFormat();
	se.GetElement<DCRTPoly>().SwitchFormat();

	se.Decode();

	se.SetLength(vectorOfInts1.size());

	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int - prime cyclotomics";

}

TEST_F(UTEncoding,string_encoding) {
	string value = "Hello, world!";
	usint m = 64;

	shared_ptr<ILParams> lp =
			ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
	EncodingParams ep( new EncodingParamsImpl(256) );
	StringEncoding	se(lp, ep, value);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetStringValue(), value ) << "string encode/decode";

	// truncate!
	shared_ptr<ILParams> lp2 =
			ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(4);
	StringEncoding	se2(lp2, ep, value);
	se2.Encode();
	se2.Decode();
	EXPECT_EQ( se2.GetStringValue(), value.substr(0, lp2->GetRingDimension()) ) << "string truncate encode/decode";
}

TEST_F(UTEncoding,integer_encoding){
	int	m = 64;
	PlaintextModulus ptm = ((uint64_t)1<<30);
	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	int64_t mv = ((uint64_t)1<<20) + (uint64_t)1;
	int64_t sv = 9;

	IntegerEncoding small(lp, ep, sv);
	IntegerEncoding smallS(lp, ep, -sv);
	IntegerEncoding medium(lp, ep, mv);
	IntegerEncoding mediumS(lp, ep, -mv);
	small.Encode();
	smallS.Encode();
	medium.Encode();
	mediumS.Encode();
	small.Decode();
	smallS.Decode();
	medium.Decode();
	mediumS.Decode();

	EXPECT_EQ( small.GetIntegerValue(), sv ) << "small";
	EXPECT_EQ( smallS.GetIntegerValue(), -sv ) << "small negative";

	EXPECT_EQ( medium.GetIntegerValue(), mv ) << "medium";
	EXPECT_EQ( mediumS.GetIntegerValue(), -mv ) << "medium negative";

	EncodingParams ep2( new EncodingParamsImpl(2) );
	IntegerEncoding one(lp, ep2, 1);
	one.Encode();
	one.Decode();
	EXPECT_EQ( one.GetIntegerValue(), 1 ) << "one";

	IntegerEncoding mone(lp, ep2, -1);
	EXPECT_THROW( mone.Encode(), config_error ) << "Encode did not throw the proper exception";
}

TEST_F(UTEncoding,fractional_encoding) {
	int	m = 64;
	PlaintextModulus ptm = ((uint64_t)1<<30);
	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
	EncodingParams ep( new EncodingParamsImpl(ptm) );

	int64_t sv = 42;
	int64_t sv0 = 0;

	// encodes 42
	FractionalEncoding psn(lp, ep, sv);
	// encodes 1/2^4
	FractionalEncoding pst(lp, ep, sv0, 4);

	psn.Encode();
	pst.Encode();
	psn.Decode();
	pst.Decode();

	EXPECT_EQ( psn.GetIntegerValue(), sv) << "small no trunc";
	EXPECT_EQ( pst.GetIntegerValue(), sv0) << "small trunc";
}

