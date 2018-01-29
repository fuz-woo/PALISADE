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
	int64_t value = 47;
	usint m = 8;
	PlaintextModulus ptm = 128;

	shared_ptr<ILParams> lp = ElemParamFactory::GenElemParams<ILParamsImpl<BigInteger>>(m);
	EncodingParams ep( new EncodingParamsImpl( ptm ) );

	ScalarEncoding	se(lp, ep, value);
	se.Encode();
	EXPECT_EQ( se.GetElement<Poly>()[0].ConvertToInt(), (uint64_t)value ) << "encoding failed";
	EXPECT_EQ( se.GetElement<Poly>()[1].ConvertToInt(), (uint64_t)0 ) << "encoding failed";

	se.Decode();
	EXPECT_EQ( se.GetScalarValue(), value ) << "positive scalar";

	ScalarEncoding	se2(lp, ep, -value);
	se2.Encode();
	se2.Decode();
	EXPECT_EQ( se2.GetScalarValue(), -value ) << "negative scalar";

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

	auto cycloPoly = GetCyclotomicPolynomial<BigVector, BigInteger>(m, modulusQ);
	ChineseRemainderTransformArb<BigInteger, BigVector>::SetCylotomicPolynomial(cycloPoly, modulusQ);

	PackedEncoding::SetParams(m, p);

	shared_ptr<ILParams> lp(new ILParams(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot));
	EncodingParams ep(new EncodingParamsImpl(p,8));

	std::vector<uint64_t> vectorOfInts1 = { 1,2,3,4,5,6,7,8,0,0 };
	PackedEncoding	se(lp, ep, vectorOfInts1);
	se.Encode();
	se.Decode();
	EXPECT_EQ( se.GetPackedValue(), vectorOfInts1 ) << "packed int";
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


