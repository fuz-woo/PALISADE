/*
 * @file matrixser.cpp - matrix serializations operations.
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

#ifndef _SRC_LIB_CORE_MATH_MATRIXSER_CPP
#define _SRC_LIB_CORE_MATH_MATRIXSER_CPP

#include "../utils/serializablehelper.h"
#include "../lattice/field2n.h"
#include "matrix.cpp"
#include "matrixstrassen.h"
using std::invalid_argument;

// this is the serializations of matricies

namespace lbcrypto {

template<>
bool Matrix<int32_t>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<int32_t>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<int32_t>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<int32_t>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<int64_t>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<int64_t>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<int64_t>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<int64_t>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<uint64_t>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<uint64_t>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<uint64_t>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<uint64_t>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<double>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<double>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<double>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<double>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<BigInteger>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<BigInteger>::Serialize() not written"<<std::endl;
	return false;
}

template<>
bool Matrix<BigInteger>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<BigInteger>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<NativeInteger>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<native_int::BigInteger>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<NativeInteger>::Deserialize(const Serialized& serObj) {
  std::cout<<"Matrix<native_int::BigInteger>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<BigVector>::Serialize(Serialized* serObj) const {
    std::cout<<"Matrix<BigVector>::Serialize() not written"<<std::endl;
	return false;
}

template<>
bool Matrix<BigVector>::Deserialize(const Serialized& serObj) {
    std::cout<<"Matrix<BigVector>::Deserialize() not written"<<std::endl;
    return false;
}

template<>
bool Matrix<Poly>::Serialize(Serialized* serObj) const {

  //TODO: this was probably never tested since Matrix<Poly>.Deserialize() is not written
        serObj->SetObject();
	//SerializeVectorOfVector("Matrix", elementName<Element>(), this->data, serObj);

	//std::cout << typeid(Element).name() << std::endl;

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
			data[r][c]->Serialize(serObj);
		}
	}

	return true;
}

template<>
bool Matrix<Poly>::Deserialize(const Serialized& serObj) {
    std::cout<<"Matrix<Poly>::Deserialize() not written"<<std::endl;
    return false;
}

template<>
bool Matrix<NativePoly>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
			data[r][c]->Serialize(serObj);
		}
	}

	return true;
}

template<>
bool Matrix<NativePoly>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<DCRTPoly>::Serialize(Serialized* serObj) const {
  std::cout <<" Matrix<DCRTPoly>::Serialize, unsupported, use SerializeMatrix"<<std::endl;
  if( !serObj->IsObject() ) {
    std::cout <<" Matrix<DCRTPoly>::Serialize, serObj is not an object"<<std::endl;
    return false;
  }
  
  for( size_t r=0; r<rows; r++ ) {
    for( size_t c=0; c<cols; c++ ) {
      data[r][c]->Serialize(serObj); //call the serialization for this matrix
    }
  }

  return true;
}

template<>
bool Matrix<DCRTPoly>::Deserialize(const Serialized& serObj) {
    std::cout <<" Matrix<DCRTPoly>::DeSerialize, not written"<<std::endl;

  return false;
}

template<>
bool MatrixStrassen<Poly>::Serialize(Serialized* serObj) const {
  std::cout<<"MatrixStrassen<Poly>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool MatrixStrassen<Poly>::Deserialize(const Serialized& serObj) {
  std::cout<<"MatrixStrassen<Poly>::Deserialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<Plaintext>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Plaintext>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<PackedEncoding>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<PackedEncoding>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Field2n>::Serialize(Serialized* serObj) const {
  std::cout<<"Matrix<Field2n>::Serialize() not written"<<std::endl;
  return false;
}

template<>
bool Matrix<Field2n>::Deserialize(const Serialized& serObj) {
	return false;
}

}

#endif
