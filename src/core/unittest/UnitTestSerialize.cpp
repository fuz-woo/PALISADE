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
  This code exercises the math libraries of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


class UnitTestSerialize : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST(UTSer,cpu_int){
	bool dbg_flag = false;
	BigInteger small(7);
	BigInteger medium(1ULL<<27 | 1ULL<<22);
	BigInteger larger(1ULL<<40 | 1ULL<<22);
	BigInteger yooge("371828316732191777888912");

	string ser;
	BigInteger deser;

	ser = small.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";

	if (dbg_flag){
	  larger.PrintLimbsInHex();
	  deser.PrintLimbsInHex();
	}

	ser = yooge.Serialize();

	DEBUG("SER "<<ser);

	deser.Deserialize(ser.c_str());
	EXPECT_EQ(yooge, deser) << "Yooge integer ser/deser fails";
}

TEST(UTSer,native_int){
	native_int::BigInteger small(7);
	native_int::BigInteger medium(1ULL<<27 | 1ULL<<22);
	native_int::BigInteger larger(1ULL<<40 | 1ULL<<22);

	string ser;
	native_int::BigInteger deser;

	ser = small.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.Serialize();
	deser.Deserialize(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";
}

TEST(UTSer,vector_of_cpu_int){
	bool dbg_flag = false;
	const int vecsize = 100;

	DEBUG("step 0");
	const BigInteger mod((uint64_t)1<<40);
	DEBUG("step 1");
	BigVector	testvec(vecsize, mod);
	DEBUG("step 2");
	Poly::DugType	dug;
	DEBUG("step 3");
	dug.SetModulus(mod);
	BigInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.SetValAtIndex(i, ranval);
	}

	DEBUG("step 4");
	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << "Serialization failed";
	DEBUG("step 5");

	BigVector newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";
	DEBUG("step 6");
	EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}

TEST(UTSer,vector_of_native_int){
	const int vecsize = 100;
	const native_int::BigInteger mod((uint64_t)1<<40);
	native_int::BigVector	testvec(vecsize, mod);
	native_int::Poly::DugType	dug;
	dug.SetModulus(mod);
	native_int::BigInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.SetValAtIndex(i, ranval);
	}

	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << "Serialization failed";

	native_int::BigVector newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilparams_test) {
	shared_ptr<Poly::Params> p = GenerateTestParams<Poly::Params,Poly::Integer>(1024, 40);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	Poly::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}


TEST(UTSer,ildcrtparams_test) {
	shared_ptr<ILDCRTParams<BigInteger>> p = GenerateDCRTParams(1024, 64, 5, 40);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	DCRTPoly::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilvector_test) {
	shared_ptr<Poly::Params> p = GenerateTestParams<Poly::Params,Poly::Integer>(1024, 40);
	Poly::DugType dug;
	Poly vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << "Serialization failed";

	Poly newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( vec, newvec ) << "Mismatch after ser/deser";

}

TEST(UTSer,ildcrtpoly_test) {
	shared_ptr<ILDCRTParams<BigInteger>> p = GenerateDCRTParams(1024, 64, 5, 40);
	DCRTPoly::DugType dug;
	DCRTPoly vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << "Serialization failed";

	DCRTPoly newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( vec, newvec ) << "Mismatch after ser/deser";

}
