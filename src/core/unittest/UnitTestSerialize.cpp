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

#include "math/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "lattice/dcrtpoly.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "lattice/elemparamfactory.h"
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

TEST(UTSer,bigint){
	bool dbg_flag = false;
	BigInteger small(7);
	BigInteger medium(1ULL<<27 | 1ULL<<22);
	BigInteger larger(1ULL<<40 | 1ULL<<22);
	BigInteger yooge("371828316732191777888912");

	string ser;
	BigInteger deser;

	ser = small.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";

	if (dbg_flag){
	  DEBUGEXP(larger.GetInternalRepresentation());
	  DEBUGEXP(deser.GetInternalRepresentation());
	}

	ser = yooge.SerializeToString();

	DEBUG("SER "<<ser);

	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(yooge, deser) << "Yooge integer ser/deser fails";
}

TEST(UTSer,native_int){
	NativeInteger small(7);
	NativeInteger medium(1ULL<<27 | 1ULL<<22);
	NativeInteger larger(1ULL<<40 | 1ULL<<22);

	string ser;
	NativeInteger deser;

	ser = small.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(small, deser) << "Small integer ser/deser fails";

	ser = medium.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(medium, deser) << "Medium integer ser/deser fails";

	ser = larger.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(larger, deser) << "Larger integer ser/deser fails";
}

TEST(UTSer,vector_of_bigint){
	bool dbg_flag = false;
	const int vecsize = 100;

	DEBUG("step 0");
	BigInteger mod((uint64_t)1<<40);
	// ///const BigInteger mod((uint64_t)1<<40);
	// uint64_t foo = ((uint64_t)1<<40);
	// BigInteger mod;
	// mod = BigInteger(foo);
	// DEBUG(sizeof(long));
	// DEBUG(sizeof(uint64_t));
	
	// NTL::ZZ ick(foo);
	// DEBUGEXP(foo);
	// DEBUGEXP(mod);
	// DEBUGEXP(mod.GetInternalRepresentation());

	// DEBUGEXP(ick);
	// mod = "9223372036854775808";
	// DEBUGEXP(mod.GetInternalRepresentation());	
	

	DEBUG("step 1");
	BigVector	testvec(vecsize, mod);
	DEBUG("step 2");
	Poly::DugType	dug;
	DEBUG("step 3");
	dug.SetModulus(mod);
	BigInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.at(i)= ranval;
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
	const NativeInteger mod((uint64_t)1<<40);
	NativeVector	testvec(vecsize, mod);
	NativePoly::DugType	dug;
	dug.SetModulus(mod);
	NativeInteger ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.at(i)= ranval;
	}

	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << "Serialization failed";

	NativeVector newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilparams_test) {
	shared_ptr<Poly::Params> p = ElemParamFactory::GenElemParams<Poly::Params>(M1024);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	Poly::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}


TEST(UTSer,ildcrtparams_test) {
	shared_ptr<ILDCRTParams<BigInteger>> p = GenerateDCRTParams<BigInteger>(1024, 5, 30);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << "Serialization failed";

	DCRTPoly::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( *p, newp ) << "Mismatch after ser/deser";
}

TEST(UTSer,ilvector_test) {
	shared_ptr<Poly::Params> p = ElemParamFactory::GenElemParams<Poly::Params>(M1024);
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
	shared_ptr<ILDCRTParams<BigInteger>> p = GenerateDCRTParams<BigInteger>(1024, 5, 30);
	DCRTPoly::DugType dug;
	DCRTPoly vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << "Serialization failed";

	DCRTPoly newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << "Deserialization failed";

	EXPECT_EQ( vec, newvec ) << "Mismatch after ser/deser";

}
TEST(UTSer,serialize_vector_bigint){
  //Serialize/DeserializeVector is a helper function to test
  //note the object has to be created outside of the function. 
  bool dbg_flag = false;
  const int vecsize = 1024;
  
  DEBUG("step 0");
  const BigInteger mod((uint64_t)1<<40);
  DEBUG("step 1");

  vector<BigInteger>testvec(vecsize);
  DEBUG("step 2");
  Poly::DugType	dug;
  DEBUG("step 3");
  dug.SetModulus(mod);
  BigInteger ranval;
  const std::string BBITypeName = ranval.IntegerTypeName();
  
  for( int i=0; i<vecsize; i++ ) {
    ranval = dug.GenerateInteger();
    testvec.push_back(ranval);
  }
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVector<BigInteger>("Vector", "BigIntegerImpl", testvec, &obj);

  //add it to the top level object
  serObj.AddMember("TestVector", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }

  DEBUG("step 5");
  
  vector <BigInteger>newvec;
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVector");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestVector";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Vector");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find Vector";
  DEBUG("step 8");

  DeserializeVector<BigInteger>("Vector", "BigIntegerImpl", mIter, &newvec);

    
  DEBUG("step 9");
  EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}


TEST(UTSer,serialize_matrix_bigint){
  bool dbg_flag = false;
  //dimensions of matrix. 
  const int nrows = 4;
  const int ncols = 8;

  
  DEBUG("step 0");
  const BigInteger mod((uint64_t)1<<40);

  DEBUG("step 1");
  Matrix<BigInteger> testmat(BigInteger::Allocator, nrows, ncols);

  DEBUG("step 2");
  Poly::DugType	dug;

  DEBUG("step 3");
  dug.SetModulus(mod);
  BigInteger ranval;

  //load up the matix with random values
  for(size_t i=0; i<nrows; i++ ) {
    for(size_t j=0; j<ncols; j++ ) {
      ranval = dug.GenerateInteger();
      testmat(i,j) = ranval;
    }
  }
  
  //build the top level serial object
  Serialized serObj;
  serObj.SetObject();

  //build the object to hold the matrix
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());
  DEBUG("step 4");
  //serialize the Matrix

  SerializeMatrix<BigInteger>("Matrix", "BigIntegerImpl", testmat, &obj);

  //add it to the top level object
  serObj.AddMember("TestMatrix", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 5");

  //have to make a shared newmatP
  ///auto newmatP = std::make_shared<Matrix<BigInteger>> (BigInteger::Allocator, 0, 0); //empty matrix
  Matrix<BigInteger> newmat(BigInteger::Allocator, 0, 0); //empty matrix
  auto newmatP = &newmat;
  
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestMatrix");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Matrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find Matrix";
  DEBUG("step 8");

  DeserializeMatrix<BigInteger>("Matrix", "BigIntegerImpl", mIter, newmatP);

    
  DEBUG("step 9");
  EXPECT_EQ( testmat, *newmatP ) << "Mismatch after ser/deser";

}
