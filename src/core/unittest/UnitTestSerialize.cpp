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
#include "lattice/backend.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"
#include "utils/parmfactory.h"
#include "lattice/elemparamfactory.h"
#include "utils/serializablehelper.h"

using namespace std;
using namespace lbcrypto;


template<typename T>
void bigint(const string& msg) {
	T small(7);
	T medium(uint64_t(1)<<27 | uint64_t(1)<<22);
	T larger(uint64_t(1)<<40 | uint64_t(1)<<22);

	string ser;
	T deser;

	ser = small.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(small, deser) << msg << " Small integer ser/deser fails";

	ser = medium.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(medium, deser) << msg << " Medium integer ser/deser fails";

	ser = larger.SerializeToString();
	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(larger, deser) << msg << " Larger integer ser/deser fails";
}

TEST(UTSer,bigint){
	RUN_ALL_BACKENDS_INT(bigint,"bigint")
}

template<typename T>
void hugeint(const string& msg) {
	T yooge("371828316732191777888912");

	string ser;
	T deser;

	ser = yooge.SerializeToString();

	deser.DeserializeFromString(ser.c_str());
	EXPECT_EQ(yooge, deser) << msg << " Huge integer ser/deser fails";
}

TEST(UTSer,hugeint){
	RUN_BIG_BACKENDS_INT(hugeint,"hugeint")
}

template<typename V>
void vector_of_bigint(const string& msg) {
	bool dbg_flag = false;
	const int vecsize = 100;

	DEBUG("step 0");
	typename V::Integer mod((uint64_t)1<<40);
	
	DEBUG("step 1");
	V	testvec(vecsize, mod);
	DEBUG("step 2");
	DiscreteUniformGeneratorImpl<V>	dug;
	DEBUG("step 3");
	dug.SetModulus(mod);
	typename V::Integer ranval;

	for( int i=0; i<vecsize; i++ ) {
		ranval = dug.GenerateInteger();
		testvec.at(i)= ranval;
	}

	DEBUG("step 4");
	Serialized	ser;
	ser.SetObject();
	ASSERT_TRUE( testvec.Serialize(&ser) ) << msg << " Serialization failed";
	DEBUG("step 5");

	V newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << msg << " Deserialization failed";
	DEBUG("step 6");
	EXPECT_EQ( testvec, newvec ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,vector_of_bigint){
	RUN_ALL_BACKENDS(vector_of_bigint, "vector_of_bigint")
}

template<typename Element>
void ilparams_test(const string& msg) {
	auto p = ElemParamFactory::GenElemParams<typename Element::Params>(1024);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << msg << " Serialization failed";

	typename Element::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << msg << " Deserialization failed";

	EXPECT_EQ( *p, newp ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,ilparams_test) {
	RUN_ALL_POLYS(ilparams_test, "ilparams_test")
}

template<typename Element>
void ildcrtparams_test(const string& msg) {
	auto p = GenerateDCRTParams<typename Element::Integer>(1024, 5, 30);
	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( p->Serialize(&ser) ) << msg << " Serialization failed";

	typename Element::Params newp;
	ASSERT_TRUE( newp.Deserialize(ser) ) << msg << " Deserialization failed";

	EXPECT_EQ( *p, newp ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,ildcrtparams_test) {
	RUN_BIG_DCRTPOLYS(ildcrtparams_test, "ildcrtparams_test")
}

template<typename Element>
void ilvector_test(const string& msg) {
	auto p = ElemParamFactory::GenElemParams<typename Element::Params>(1024);
	typename Element::DugType dug;
	Element vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << msg << " Serialization failed";

	Element newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << msg << " Deserialization failed";

	EXPECT_EQ( vec, newvec ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,ilvector_test) {
	RUN_ALL_POLYS(ilvector_test, "ilvector_test")
}

template<typename Element>
void ildcrtpoly_test(const string& msg) {
	auto p = GenerateDCRTParams<typename Element::Integer>(1024, 5, 30);
	typename Element::DugType dug;
	Element vec(dug, p);

	Serialized ser;
	ser.SetObject();
	ASSERT_TRUE( vec.Serialize(&ser) ) << msg << " Serialization failed";

	Element newvec;
	ASSERT_TRUE( newvec.Deserialize(ser) ) << msg << " Deserialization failed";

	EXPECT_EQ( vec, newvec ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,ildcrtpoly_test) {
	RUN_BIG_DCRTPOLYS(ildcrtpoly_test, "ildcrtpoly_test")
}

template<typename V>
void serialize_vector_bigint(const string& msg) {
  //Serialize/DeserializeVector is a helper function to test
  //note the object has to be created outside of the function. 
  bool dbg_flag = false;
  const int vecsize = 1024;
  
  DEBUG("step 0");
  const typename V::Integer mod((uint64_t)1<<40);
  DEBUG("step 1");

  vector<typename V::Integer>testvec(vecsize);
  DEBUG("step 2");
  DiscreteUniformGeneratorImpl<V>	dug;
  DEBUG("step 3");
  dug.SetModulus(mod);
  typename V::Integer ranval;
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
  SerializeVector<typename V::Integer>("Vector", "BigIntegerImpl", testvec, &obj);

  //add it to the top level object
  serObj.AddMember("TestVector", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }

  DEBUG("step 5");
  
  vector <typename V::Integer>newvec;
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestVector");
  DEBUG("step 6");

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << msg << "Can't find TestVector";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Vector");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() )<< msg << " Can't find Vector";
  DEBUG("step 8");

  DeserializeVector<typename V::Integer>("Vector", "BigIntegerImpl", mIter, &newvec);

    
  DEBUG("step 9");
  EXPECT_EQ( testvec, newvec ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer, serialize_vector_bigint){
	RUN_ALL_BACKENDS(serialize_vector_bigint,"serialize_vector_bigint")
}

////////////////////////////////////////////////////////////
template<typename V>
void serialize_matrix_bigint(const string& msg) {
  bool dbg_flag = false;
  //dimensions of matrix. 
  const int nrows = 4;
  const int ncols = 8;

  
  DEBUG("step 0");
  const typename V::Integer mod((uint64_t)1<<40);

  DEBUG("step 1");
  Matrix<typename V::Integer> testmat(V::Integer::Allocator, nrows, ncols);

  DEBUG("step 2");
  DiscreteUniformGeneratorImpl<V>	dug;

  DEBUG("step 3");
  dug.SetModulus(mod);
  typename V::Integer ranval;

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

  SerializeMatrix<typename V::Integer>("Matrix", "BigIntegerImpl", testmat, &obj);

  //add it to the top level object
  serObj.AddMember("TestMatrix", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 5");

  Matrix<typename V::Integer> newmat(V::Integer::Allocator, 0, 0); //empty matrix
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

  DeserializeMatrix<typename V::Integer>("Matrix", "BigIntegerImpl", mIter, newmatP);
    
  DEBUG("step 9");
  EXPECT_EQ( testmat, *newmatP ) << msg << " Mismatch after ser/deser";
  DEBUGEXP(testmat);
  DEBUGEXP(*newmatP);
}

TEST(UTSer, serialize_matrix_bigint){
	RUN_ALL_BACKENDS(serialize_matrix_bigint,"serialize_matrix_bigint")
}

////////////////////////////////////////////////////////////////////////

template<typename Element>
void serialize_vector_of_p(const string& msg) {
  bool dbg_flag = false;

  DEBUG("step 1");
  
  //generate three pointers
  shared_ptr<typename Element::Params> p1 = ElemParamFactory::GenElemParams<typename Element::Params>(512);
  
  shared_ptr<typename Element::Params> p2 = ElemParamFactory::GenElemParams<typename Element::Params>(1024);
  
  shared_ptr<typename Element::Params> p3 = ElemParamFactory::GenElemParams<typename Element::Params>(2048);
  
  DEBUG("step 2");
  //build the vector to pointers
  vector<shared_ptr<typename Element::Params>> test_v(3);
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
  SerializeVectorOfPointers<typename Element::Params>("Vector", "ILParams", test_v, &obj);
						      
 
  //add it to the top level object
  serObj.AddMember("TestVector", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 4");  

  vector<shared_ptr<typename Element::Params>> new_v(3);

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

  DeserializeVectorOfPointers<typename Element::Params>("Vector", "ILParams", mIter, &new_v);
    
  DEBUG("step 9");

  DEBUGEXP(new_v);
  DEBUGEXP(new_v.size());
  
  for (size_t i = 0; i< test_v.size(); i++){
    DEBUGEXP(test_v[i]);
    DEBUGEXP(*(test_v[i]));
    DEBUGEXP(new_v[i]);
    DEBUGEXP(*(new_v[i]));
    EXPECT_EQ( *(test_v[i]), *(new_v[i]) ) << msg << " Mismatch after ser/deser index "<<i;
  }
}

TEST(UTSer,serialize_vector_of_p) {
	RUN_ALL_POLYS(serialize_vector_of_p, "serialize_vector_of_p")
}

///////


template<typename Element>
void serialize_map_of_p(const string& msg) {
  bool dbg_flag = false;

  DEBUG("step 1");
  
  //generate three pointers
  shared_ptr<typename Element::Params> p1 = ElemParamFactory::GenElemParams<typename Element::Params>(16);
  
  shared_ptr<typename Element::Params> p2 = ElemParamFactory::GenElemParams<typename Element::Params>(1024);
  
  shared_ptr<typename Element::Params> p3 = ElemParamFactory::GenElemParams<typename Element::Params>(2048);
  
  DEBUG("step 2");
  
  //build the map to pointers
  map<usint, shared_ptr<typename Element::Params>> test_map;

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
  SerializeMapOfPointers<usint, typename Element::Params>("Map", "ILParams", test_map, &obj);
						      
 
  //add it to the top level object
  serObj.AddMember("TestMap", obj, serObj.GetAllocator());
  
  if (dbg_flag) {
    // write the result to cout for debug
    std::string jsonstring;
    SerializableHelper::SerializationToPrettyString(serObj, jsonstring);
    std::cout<<jsonstring<<std::endl;
  }
  DEBUG("step 4");  

  map<usint, shared_ptr<typename Element::Params>> new_map;

  DEBUG("step 5");  
  //top level iterator
  SerialItem::ConstMemberIterator topIter = serObj.FindMember("TestMap");
  DEBUG("step 6");
  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << msg << " Can't find TestMap";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("Map");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() ) << msg << " Can't find Map";
  DEBUG("step 8");

  DeserializeMapOfPointers<usint, typename Element::Params>("Map", "ILParams", mIter, &new_map);
    
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
    EXPECT_EQ( *(test_map[i]), *(new_map[i]) ) << msg << " Mismatch after ser/deser index "<<i;
  }
}

TEST(UTSer,serialize_map_of_p) {
	RUN_ALL_POLYS(serialize_map_of_p, "serialize_map_of_p")
}

//////

template<typename T>
void serialize_vector_matrix(const string& msg) {
  //Serialize/DeserializeVectorOfMatrix is a helper function to test
  //note the object has to be created outside of the function.
  
  bool dbg_flag = false;
  const int vecsize = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<Matrix<T>> testvec(vecsize, Matrix<T>(T::Allocator, 0, 0));
  
  vector <Matrix<T>> newvec(vecsize, Matrix<T>(T::Allocator, 0, 0));
  DEBUG("step 1");
  //build test input matricies
  usint nrows(3);
  usint ncols(5);
  //zero matricies
  Matrix<T> zeromat(T::Allocator, 0,0);
  Matrix<T> testmat0(T::Allocator, 0,0);
  Matrix<T> testmat1(T::Allocator, 0,0);
  Matrix<T> testmat2(T::Allocator, 0,0);
  Matrix<T> testmat3(T::Allocator, 0,0);

  Matrix<T> *tm_p; //pointer to a M<I>
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
	(*tm_p)(row,col) = T(100*i + 10*row + col); //a unique value
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
  SerializeVectorOfMatrix<T>("VectorOfMatrix", "BigIntegerImpl", testvec, &obj);

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

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << msg << " Can't find TestVectorOfMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() ) << msg << " Can't find VectorOfMatrix";
  DEBUG("step 8");

  DeserializeVectorOfMatrix<T>("VectorOfMatrix", "BigIntegerImpl", mIter, &newvec);
  DEBUG("step 9");
  EXPECT_EQ( testvec, newvec ) << msg << " Mismatch after ser/deser";
}

TEST(UTSer,serialize_vector_matrix){
	RUN_ALL_BACKENDS_INT(serialize_vector_matrix,"serialize_vector_matrix")
}

////////////////////////////////////////////////////////////////

template<typename T>
void serialize_vector_pointers_matrix(const string& msg) {
  //Serialize/DeserializeVectorOfPointersToMatrix is a helper function to test
  //note the object has to be created outside of the function.
  
  bool dbg_flag = false;
  const int vecsize = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<shared_ptr<Matrix<T>>> testvec(vecsize);
  
  vector <shared_ptr<Matrix<T>>> newvec(vecsize);
  DEBUG("step 1");
  //build test input matricies
  usint nrows(2);
  usint ncols(2);

  Matrix<T> zeromat(T::Allocator, 0,0);
  Matrix<T> testmat3(T::Allocator, 0,0);

  DEBUG("step 3");
 
  for (usint i = 0; i < vecsize; i++) {
    //point to zero matricies
    auto tm_p = make_shared<Matrix<T>>(T::Allocator, 0,0);
    tm_p->SetSize(nrows+i, ncols+i); 
    for (usint row = 0; row < nrows+i; row++) {
      for (usint col = 0; col < ncols+i; col++){ 
	(*tm_p)(row,col) = T(100*i + 10*row + col); //a unique value
      }
    }
    testvec[i]=tm_p;
    newvec[i] = make_shared<Matrix<T>>(T::Allocator, 0,0); //zero matrix
  }
  
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVectorOfPointersToMatrix<T>("VectorOfPointersToMatrix", "BigIntegerImpl",
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

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << msg << " Can't find TestVectorOfPointersToMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfPointersToMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() ) << msg << " Can't find VectorOfPointersToMatrix";
  DEBUG("step 8");

  DeserializeVectorOfPointersToMatrix<T>("VectorOfPointersToMatrix", "BigIntegerImpl", mIter, &newvec);
    
  DEBUG("step 9");
  auto it1 = testvec.begin();
  auto it2 = newvec.begin();
  auto i = 0;
  for (; (it1 != testvec.end())&&(it2 != newvec.end()); it1++, it2++, i++){
    DEBUG("testing "<<i);
    EXPECT_EQ( **it1, **it2 ) << msg << " Mismatch after ser/deser in entry "<<i;
  }
}

TEST(UTSer,serialize_vector_pointers_matrix){
	RUN_ALL_BACKENDS_INT(serialize_vector_pointers_matrix,"serialize_vector_pointers_matrix")
}

//need tests for

// (De)SerializeVectorOfVectorOfPointersToMatrix [in lwe S compiles D not done]

////////////////////////////////////////////////////////////////

template<typename T>
void serialize_vector_vector_pointers_matrix(const string& msg) {
  // Serialize/DeserializeVectorOfVectorOfPointersToMatrix
  // is a helper function to test
  
  bool dbg_flag = false;
  const int vec1_size = 3;
  const int vec2_size = 4;
  
  DEBUG("step 0");
  //build test vector (note needs allocator for Matrix<>
  vector<vector<shared_ptr<Matrix<T>>>> testvec(vec1_size);
  
  vector<vector <shared_ptr<Matrix<T>>>> newvec(vec2_size);
  DEBUG("step 1");
  //build test input matricies
  usint nrows(2);
  usint ncols(3);

  DEBUG("step 3");
 
  for (usint i = 0; i < vec1_size; i++) {
    for (usint j = 0; j < vec2_size; j++) {
      //point to zero matricies
      auto tm_p = make_shared<Matrix<T>>(T::Allocator, 0,0);
      tm_p->SetSize(nrows+i, ncols+i); 
      for (usint row = 0; row < nrows+i; row++) {
	for (usint col = 0; col < ncols+i; col++){
	  //write a unique value
	  (*tm_p)(row,col) = T(1000*i+100*j + 10*row + col);
	}
      }
      testvec[i].push_back(tm_p);
      newvec[i].push_back( make_shared<Matrix<T>>(T::Allocator, 0,0)); //zero matrix
    }
  }
  
  DEBUG("step 4");
  //build the top level serial object
  Serialized	serObj;
  serObj.SetObject();

  //build the object to hold the vector
  Serialized obj(rapidjson::kObjectType, &serObj.GetAllocator());

  //serialize the vector
  SerializeVectorOfVectorOfPointersToMatrix<T>("VectorOfVectorOfPointersToMatrix", "BigIntegerImpl",
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

  
  ASSERT_FALSE (topIter == serObj.MemberEnd()) << msg << " Can't find TestVectorOfVectorOfPointersToMatrix";

  //iterate over next level
  SerialItem::ConstMemberIterator mIter=topIter->value.FindMember("VectorOfVectorOfPointersToMatrix");

  DEBUG("step 7");

  ASSERT_FALSE (mIter == topIter->value.MemberEnd() ) << msg << " Can't find VectorOfVectorOfPointersToMatrix";
  DEBUG("step 8");

  DeserializeVectorOfVectorOfPointersToMatrix<T>("VectorOfVectorOfPointersToMatrix", "BigIntegerImpl", mIter, &newvec);
    
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
	<< msg << " Mismatch after ser/deser in entry "<<i<<", "<<j;
    }
  }
}


TEST(UTSer,serialize_vector_vector_pointers_matrix){
	RUN_ALL_BACKENDS_INT(serialize_vector_vector_pointers_matrix,"serialize_vector_vector_pointers_matrix")
}
