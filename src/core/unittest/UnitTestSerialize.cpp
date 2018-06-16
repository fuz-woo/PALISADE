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
	shared_ptr<Poly::Params> p = ElemParamFactory::GenElemParams<Poly::Params>(1024);
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
	shared_ptr<Poly::Params> p = ElemParamFactory::GenElemParams<Poly::Params>(1024);
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
TEST(UTSer, serialize_vector_bigint){
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

////////////////////////////////////////////////////////////
TEST(UTSer, serialize_matrix_bigint){
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
  DEBUGEXP(testmat);
  DEBUGEXP(*newmatP);

}
////////////////////////////////////////////////////////////////////////

TEST(UTSer, serialize_vector_of_p) {
  bool dbg_flag = false;

  DEBUG("step 1");
  
  //generate three pointers
  shared_ptr<Poly::Params> p1 = ElemParamFactory::GenElemParams<Poly::Params>(512);
  
  shared_ptr<Poly::Params> p2 = ElemParamFactory::GenElemParams<Poly::Params>(1024);
  
  shared_ptr<Poly::Params> p3 = ElemParamFactory::GenElemParams<Poly::Params>(2048);
  
  DEBUG("step 2");
  //build the vector to pointers
  vector<shared_ptr<Poly::Params>> test_v(3); 
  DEBUG("step 2.1");
  test_v[0]=p1;
  test_v[1]=p2;
  test_v[2]=p3;
  DEBUG("step 2.2");  
  //build the top level serial object
  Serialized serObj;
  DEBUG("step 2.3");  
  serObj.SetObject();
  DEBUG("step 2.4");  
  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  DEBUG("step 3");  
  //serialize the vector
  SerializeVectorOfPointers<Poly::Params>("Vector", "ILParams", test_v, &obj);
						      
 
  //add it to the top level object
  serObj.AddMember("TestVector", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 4");  

  vector<shared_ptr<Poly::Params>> new_v(3);

  DEBUG("step 5");  
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVector");
  DEBUG("step 6");
  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestVector";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Vector");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find Vector";
  DEBUG("step 8");

  DeserializeVectorOfPointers<Poly::Params>("Vector", "ILParams", mIter, &new_v);
    
  DEBUG("step 9");

  DEBUGEXP(new_v);
  DEBUGEXP(new_v.size());
  
  for (size_t i = 0; i< test_v.size(); i++){
    DEBUGEXP(test_v[i]);
    DEBUGEXP(*(test_v[i]));
    DEBUGEXP(new_v[i]);
    DEBUGEXP(*(new_v[i]));
    EXPECT_EQ( *(test_v[i]), *(new_v[i]) ) << "Mismatch after ser/deser index "<<i;
  }
}
///////


TEST(UTSer, serialize_map_of_p) {
  bool dbg_flag = false;

  DEBUG("step 1");
  
  //generate three pointers
  shared_ptr<Poly::Params> p1 = ElemParamFactory::GenElemParams<Poly::Params>(16);
  
  shared_ptr<Poly::Params> p2 = ElemParamFactory::GenElemParams<Poly::Params>(1024);
  
  shared_ptr<Poly::Params> p3 = ElemParamFactory::GenElemParams<Poly::Params>(2048);
  
  DEBUG("step 2");
  
  //build the map to pointers
  map<usint, shared_ptr<Poly::Params>> test_map;

  DEBUG("step 2.1");
  test_map[0]=p1;
  test_map[1]=p2;
  test_map[2]=p3;


  DEBUG("step 2.2");  
  //build the top level serial object
  Serialized serObj;
  DEBUG("step 2.3");  
  serObj.SetObject();
  DEBUG("step 2.4");  
  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  DEBUG("step 3");  
  //serialize the vector
  SerializeMapOfPointers<usint, Poly::Params>("Map", "ILParams", test_map, &obj);
						      
 
  //add it to the top level object
  serObj.AddMember("TestMap", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 4");  

  map<usint, shared_ptr<Poly::Params>> new_map;

  DEBUG("step 5");  
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestMap");
  DEBUG("step 6");
  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestMap";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Map");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find Map";
  DEBUG("step 8");

  DeserializeMapOfPointers<usint, Poly::Params>("Map", "ILParams", mIter, &new_map);
    
  DEBUG("step 9");
  
  //DEBUGEXP(new_map);
  DEBUGEXP(new_map.size());
  if (dbg_flag) {
    for(auto elem : new_map) {
      DEBUG( elem.first);
      DEBUG( *(elem.second));
    }
  }
  
  for (size_t i = 0; i< test_map.size(); i++){
    DEBUGEXP(test_map[i]);
    DEBUGEXP(*(test_map[i]));
    DEBUGEXP(new_map[i]);
    DEBUGEXP(*(new_map[i]));
    EXPECT_EQ( *(test_map[i]), *(new_map[i]) ) << "Mismatch after ser/deser index "<<i;
  }
}

//////

TEST(UTSer, serialize_vector_matrix){
  //Serialize/DeserializeVectorOfMatrix is a helper function to test
  //note the object has to be created outside of the function.
  
  bool dbg_flag = false;
  const int vecsize = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<Matrix<BigInteger>> testvec(vecsize, Matrix<BigInteger>(BigInteger::Allocator, 0, 0));
  
  vector <Matrix<BigInteger>> newvec(vecsize, Matrix<BigInteger>(BigInteger::Allocator, 0, 0));
  DEBUG("step 1");
  //build test input matricies
  usint nrows(3);
  usint ncols(5);
  //zero matricies
  Matrix<BigInteger> zeromat(BigInteger::Allocator, 0,0);
  Matrix<BigInteger> testmat0(BigInteger::Allocator, 0,0);
  Matrix<BigInteger> testmat1(BigInteger::Allocator, 0,0);
  Matrix<BigInteger> testmat2(BigInteger::Allocator, 0,0);
  Matrix<BigInteger> testmat3(BigInteger::Allocator, 0,0);

  Matrix<BigInteger> *tm_p; //pointer to a M<I>
  DEBUG("step 3");
 
  for (usint i = 0; i < vecsize; i++) {
    switch (i) {
    case 0:
      tm_p = &testmat0;
      break;
    case 1:
      tm_p = &testmat1;
      break;
    case 2:
      tm_p = &testmat2;
      break;
    case 3:
      tm_p = &testmat3;
      break;

    }
    tm_p->SetSize(nrows+i, ncols+i); 
    for (usint row = 0; row < nrows+i; row++) {
      for (usint col = 0; col < ncols+i; col++){ 
	(*tm_p)(row,col) = BigInteger(100*i + 10*row + col); //a unique value
      }
    }
    testvec[i] = *tm_p;
    newvec[i] = zeromat;
  }
  
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVectorOfMatrix<BigInteger>("VectorOfMatrix", "BigIntegerImpl", testvec, &obj);

  //add it to the top level object
  serObj.AddMember("TestVectorOfMatrix", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }

  DEBUG("step 5");

  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVectorOfMatrix");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestVectorOfMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find VectorOfMatrix";
  DEBUG("step 8");

  //DeserializeVectorOfMatrix<BigInteger>("VectorOfMatrix", "BigIntegerImpl", mIter, &newvec /*, BigInteger::Allocator*/);
    DeserializeVectorOfMatrix<BigInteger>("VectorOfMatrix", "BigIntegerImpl", mIter, &newvec);
  DEBUG("step 9");
  EXPECT_EQ( testvec, newvec ) << "Mismatch after ser/deser";
}




////////////////////////////////////////////////////////////////

TEST(UTSer, serialize_vector_pointers_matrix){
  //Serialize/DeserializeVectorOfPointersToMatrix is a helper function to test
  //note the object has to be created outside of the function.
  
  bool dbg_flag = false;
  const int vecsize = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<shared_ptr<Matrix<BigInteger>>> testvec(vecsize);
  
  vector <shared_ptr<Matrix<BigInteger>>> newvec(vecsize);
  DEBUG("step 1");
  //build test input matricies
  usint nrows(2);
  usint ncols(2);

  Matrix<BigInteger> zeromat(BigInteger::Allocator, 0,0);
  Matrix<BigInteger> testmat3(BigInteger::Allocator, 0,0);

  DEBUG("step 3");
 
  for (usint i = 0; i < vecsize; i++) {
    //point to zero matricies
    auto tm_p = make_shared<Matrix<BigInteger>>(BigInteger::Allocator, 0,0);
    tm_p->SetSize(nrows+i, ncols+i); 
    for (usint row = 0; row < nrows+i; row++) {
      for (usint col = 0; col < ncols+i; col++){ 
	(*tm_p)(row,col) = BigInteger(100*i + 10*row + col); //a unique value
      }
    }
    testvec[i]=tm_p;
    newvec[i] = make_shared<Matrix<BigInteger>>(BigInteger::Allocator, 0,0); //zero matrix
  }
  
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVectorOfPointersToMatrix<BigInteger>("VectorOfPointersToMatrix", "BigIntegerImpl",
					       testvec, &obj);

  //add it to the top level object
  serObj.AddMember("TestVectorOfPointersToMatrix", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }

  DEBUG("step 5");

  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVectorOfPointersToMatrix");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestVectorOfPointersToMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfPointersToMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find VectorOfPointersToMatrix";
  DEBUG("step 8");

  DeserializeVectorOfPointersToMatrix<BigInteger>("VectorOfPointersToMatrix", "BigIntegerImpl", mIter, &newvec);
    
  DEBUG("step 9");
  auto it1 = testvec.begin();
  auto it2 = newvec.begin();
  auto i = 0;
  for (; (it1 != testvec.end())&&(it2 != newvec.end()); it1++, it2++, i++){
    DEBUG("testing "<<i);
    EXPECT_EQ( **it1, **it2 ) << "Mismatch after ser/deser in entry "<<i;
  }
}


//need tests for

// (De)SerializeVectorOfVectorOfPointersToMatrix [in lwe S compiles D not done]

////////////////////////////////////////////////////////////////

TEST(UTSer, serialize_vector_vector_pointers_matrix){
  // Serialize/DeserializeVectorOfVectorOfPointersToMatrix
  // is a helper function to test
  
  bool dbg_flag = false;
  const int vec1_size = 3;
  const int vec2_size = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<vector<shared_ptr<Matrix<BigInteger>>>> testvec(vec1_size);
  
  vector<vector <shared_ptr<Matrix<BigInteger>>>> newvec(vec2_size);
  DEBUG("step 1");
  //build test input matricies
  usint nrows(2);
  usint ncols(3);

  DEBUG("step 3");
 
  for (usint i = 0; i < vec1_size; i++) {
    for (usint j = 0; j < vec2_size; j++) {
      //point to zero matricies
      auto tm_p = make_shared<Matrix<BigInteger>>(BigInteger::Allocator, 0,0);
      tm_p->SetSize(nrows+i, ncols+i); 
      for (usint row = 0; row < nrows+i; row++) {
	for (usint col = 0; col < ncols+i; col++){
	  //write a unique value
	  (*tm_p)(row,col) = BigInteger(1000*i+100*j + 10*row + col); 
	}
      }
      testvec[i].push_back(tm_p);
      newvec[i].push_back( make_shared<Matrix<BigInteger>>(BigInteger::Allocator, 0,0)); //zero matrix
    }
  }
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVectorOfVectorOfPointersToMatrix<BigInteger>("VectorOfVectorOfPointersToMatrix", "BigIntegerImpl",
					       testvec, &obj);

  //add it to the top level object
  serObj.AddMember("TestVectorOfVectorOfPointersToMatrix", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }

  DEBUG("step 5");

  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVectorOfVectorOfPointersToMatrix");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << "Cant find TestVectorOfVectorOfPointersToMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfVectorOfPointersToMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< "Cant find VectorOfVectorOfPointersToMatrix";
  DEBUG("step 8");

  DeserializeVectorOfVectorOfPointersToMatrix<BigInteger>("VectorOfVectorOfPointersToMatrix", "BigIntegerImpl", mIter, &newvec);
    
  DEBUG("step 9");
  //double loop over vector of vector, and dereference matrix and compare
  auto it_1_1 = testvec.begin();
  auto it_1_2 = newvec.begin();
  auto i = 0;
  for (; (it_1_1 != testvec.end())&&(it_1_2 != newvec.end());
       it_1_1++, it_1_2++, i++) {

    auto it_2_1 = it_1_1->begin();
    auto it_2_2 = it_1_2->begin();
    auto j = 0;
    for (; (it_2_1 != it_1_1->end())&&(it_2_2 != it_1_2->end());
	 it_2_1++, it_2_2++, j++) {
      
      //compare dereferenced matricies
      EXPECT_EQ( **it_2_1, **it_2_2 )
	<< "Mismatch after ser/deser in entry "<<i<<", "<<j;
    }
  }
}

