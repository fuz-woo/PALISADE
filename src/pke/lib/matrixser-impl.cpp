/*
 * @file matrixser-impl.cpp - matrix serialization implementation
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

// this is the implementation of matrixes of things that are in pke

// FIXME there is much duplicated redundant code here, and we should do this better

#include "palisade.h"
#include "cryptocontext.h"
#include "utils/serializablehelper.h"
#include "rationalciphertext.h"

#include "math/matrix.cpp"
using std::invalid_argument;

namespace lbcrypto {

template class Matrix<Ciphertext<Poly>>;
template class Matrix<RationalCiphertext<Poly>>;
template class Matrix<Ciphertext<NativePoly>>;
template class Matrix<RationalCiphertext<NativePoly>>;
template class Matrix<Ciphertext<DCRTPoly>>;
template class Matrix<RationalCiphertext<DCRTPoly>>;

template<>
bool Matrix<RationalCiphertext<Poly>>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "Matrix", serObj->GetAllocator());
	serObj->AddMember("ElementObject", "RationalCiphertext<Poly>", serObj->GetAllocator());
	serObj->AddMember("Rows", std::to_string(rows), serObj->GetAllocator());
	serObj->AddMember("Cols", std::to_string(cols), serObj->GetAllocator());

	int elCount = 0;

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
			Serialized elSer(rapidjson::kObjectType, &serObj->GetAllocator());

			if( (*this)(r,c).Serialize(&elSer) == false )
				return false;

			Serialized fullElSer(rapidjson::kObjectType, &serObj->GetAllocator());

			fullElSer.AddMember("row", std::to_string(r), serObj->GetAllocator());
			fullElSer.AddMember("col", std::to_string(c), serObj->GetAllocator());
			fullElSer.AddMember("entry", elSer.Move(), serObj->GetAllocator());

			SerialItem key( std::to_string(elCount), serObj->GetAllocator() );
			serObj->AddMember(key, fullElSer.Move(), serObj->GetAllocator());

			elCount++;
		}
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<Poly>>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Matrix" )
		return false;

	mIter = serObj.FindMember("ElementObject");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "RationalCiphertext<Poly>" )
		return false;

	mIter = serObj.FindMember("Rows");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mrows = std::stoi( mIter->value.GetString() );

	mIter = serObj.FindMember("Cols");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mcols = std::stoi( mIter->value.GetString() );

	auto tempElement = this->allocZero();
	CryptoContext<Poly> cc = tempElement->GetCryptoContext();

	if( bool(cc) == false )
		return false;

	this->SetSize(mrows, mcols);

	for( size_t i=0; i<rows*cols; i++ ) {
		mIter = serObj.FindMember( std::to_string(i) );
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized oneItem(rapidjson::kObjectType);
		SerialItem val( mIter->value, oneItem.GetAllocator() );
		val.Swap(oneItem);

		mIter = oneItem.FindMember("row");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisRow = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("col");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisCol = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("entry");
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized mEntry(rapidjson::kObjectType);
		SerialItem mVal( mIter->value, mEntry.GetAllocator() );
		mVal.Swap(mEntry);

		RationalCiphertext<Poly> entry(cc);

		if( entry.Deserialize(mEntry) == false )
			return false;

		(*this)(thisRow,thisCol) = std::move(entry);
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<NativePoly>>::Serialize(Serialized* serObj) const {
	serObj->SetObject();

	serObj->AddMember("Object", "Matrix", serObj->GetAllocator());
	serObj->AddMember("ElementObject", "RationalCiphertext<NativePoly>", serObj->GetAllocator());
	serObj->AddMember("Rows", std::to_string(rows), serObj->GetAllocator());
	serObj->AddMember("Cols", std::to_string(cols), serObj->GetAllocator());

	int elCount = 0;

	for( size_t r=0; r<rows; r++ ) {
		for( size_t c=0; c<cols; c++ ) {
			Serialized elSer(rapidjson::kObjectType, &serObj->GetAllocator());

			if( (*this)(r,c).Serialize(&elSer) == false )
				return false;

			Serialized fullElSer(rapidjson::kObjectType, &serObj->GetAllocator());

			fullElSer.AddMember("row", std::to_string(r), serObj->GetAllocator());
			fullElSer.AddMember("col", std::to_string(c), serObj->GetAllocator());
			fullElSer.AddMember("entry", elSer.Move(), serObj->GetAllocator());

			SerialItem key( std::to_string(elCount), serObj->GetAllocator() );
			serObj->AddMember(key, fullElSer.Move(), serObj->GetAllocator());

			elCount++;
		}
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<NativePoly>>::Deserialize(const Serialized& serObj) {
	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Matrix" )
		return false;

	mIter = serObj.FindMember("ElementObject");
	if( mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "RationalCiphertext<NativePoly>" )
		return false;

	mIter = serObj.FindMember("Rows");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mrows = std::stoi( mIter->value.GetString() );

	mIter = serObj.FindMember("Cols");
	if( mIter == serObj.MemberEnd() )
		return false;

	int mcols = std::stoi( mIter->value.GetString() );

	auto tempElement = this->allocZero();
	CryptoContext<NativePoly> cc = tempElement->GetCryptoContext();

	if( bool(cc) == false )
		return false;

	this->SetSize(mrows, mcols);

	for( size_t i=0; i<rows*cols; i++ ) {
		mIter = serObj.FindMember( std::to_string(i) );
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized oneItem(rapidjson::kObjectType);
		SerialItem val( mIter->value, oneItem.GetAllocator() );
		val.Swap(oneItem);

		mIter = oneItem.FindMember("row");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisRow = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("col");
		if( mIter == serObj.MemberEnd() )
			return false;

		int thisCol = std::stoi( mIter->value.GetString() );

		mIter = oneItem.FindMember("entry");
		if( mIter == serObj.MemberEnd() )
			return false;

		Serialized mEntry(rapidjson::kObjectType);
		SerialItem mVal( mIter->value, mEntry.GetAllocator() );
		mVal.Swap(mEntry);

		RationalCiphertext<NativePoly> entry(cc);

		if( entry.Deserialize(mEntry) == false )
			return false;

		(*this)(thisRow,thisCol) = std::move(entry);
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<DCRTPoly>>::Serialize(Serialized* serObj) const {

	serObj->SetObject();

	serObj->AddMember("Object", "Matrix", serObj->GetAllocator());
	serObj->AddMember("ElementObject", "RationalCiphertext<DCRTPoly>", serObj->GetAllocator());
	serObj->AddMember("Rows", std::to_string(rows), serObj->GetAllocator());
	serObj->AddMember("Cols", std::to_string(cols), serObj->GetAllocator());

	int elCount = 0;

	for (size_t r = 0; r<rows; r++) {
		for (size_t c = 0; c<cols; c++) {
			Serialized elSer(rapidjson::kObjectType, &serObj->GetAllocator());

			if ((*this)(r, c).Serialize(&elSer) == false)
				return false;

			Serialized fullElSer(rapidjson::kObjectType, &serObj->GetAllocator());

			fullElSer.AddMember("row", std::to_string(r), serObj->GetAllocator());
			fullElSer.AddMember("col", std::to_string(c), serObj->GetAllocator());
			fullElSer.AddMember("entry", elSer.Move(), serObj->GetAllocator());

			SerialItem key(std::to_string(elCount), serObj->GetAllocator());
			serObj->AddMember(key, fullElSer.Move(), serObj->GetAllocator());

			elCount++;
		}
	}

	return true;
}

template<>
bool Matrix<RationalCiphertext<DCRTPoly>>::Deserialize(const Serialized& serObj) {

	Serialized::ConstMemberIterator mIter = serObj.FindMember("Object");
	if (mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "Matrix")
		return false;

	mIter = serObj.FindMember("ElementObject");
	if (mIter == serObj.MemberEnd() || string(mIter->value.GetString()) != "RationalCiphertext<DCRTPoly>")
		return false;

	mIter = serObj.FindMember("Rows");
	if (mIter == serObj.MemberEnd())
		return false;

	int mrows = std::stoi(mIter->value.GetString());

	mIter = serObj.FindMember("Cols");
	if (mIter == serObj.MemberEnd())
		return false;

	int mcols = std::stoi(mIter->value.GetString());

	auto tempElement = this->allocZero();
	CryptoContext<DCRTPoly> cc = tempElement->GetCryptoContext();

	if (bool(cc) == false)
		return false;

	this->SetSize(mrows, mcols);

	for (size_t i = 0; i<rows*cols; i++) {
		mIter = serObj.FindMember(std::to_string(i));
		if (mIter == serObj.MemberEnd())
			return false;

		Serialized oneItem(rapidjson::kObjectType);
		SerialItem val(mIter->value, oneItem.GetAllocator());
		val.Swap(oneItem);

		mIter = oneItem.FindMember("row");
		if (mIter == serObj.MemberEnd())
			return false;

		int thisRow = std::stoi(mIter->value.GetString());

		mIter = oneItem.FindMember("col");
		if (mIter == serObj.MemberEnd())
			return false;

		int thisCol = std::stoi(mIter->value.GetString());

		mIter = oneItem.FindMember("entry");
		if (mIter == serObj.MemberEnd())
			return false;

		Serialized mEntry(rapidjson::kObjectType);
		SerialItem mVal(mIter->value, mEntry.GetAllocator());
		mVal.Swap(mEntry);

		RationalCiphertext<DCRTPoly> entry(cc);

		if (entry.Deserialize(mEntry) == false)
			return false;

		(*this)(thisRow, thisCol) = std::move(entry);
	}

	return true;
}

template<>
bool Matrix<Ciphertext<Poly>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Ciphertext<Poly>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Ciphertext<NativePoly>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Ciphertext<NativePoly>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
bool Matrix<Ciphertext<DCRTPoly>>::Serialize(Serialized* serObj) const {
	return false;
}

template<>
bool Matrix<Ciphertext<DCRTPoly>>::Deserialize(const Serialized& serObj) {
	return false;
}

template<>
Matrix<RationalCiphertext<Poly>>& Matrix<RationalCiphertext<Poly>>::Ones() {
	throw std::logic_error("Cannot fill matrix of ciphertext with 1's");
}

template<>
Matrix<RationalCiphertext<Poly>>& Matrix<RationalCiphertext<Poly>>::Identity() {
	throw std::logic_error("Cannot create identity matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<Poly>> Matrix<RationalCiphertext<Poly>>::GadgetVector(int64_t base) const {
	throw std::logic_error("Cannot create gadget matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<NativePoly>>& Matrix<RationalCiphertext<NativePoly>>::Ones() {
	throw std::logic_error("Cannot fill matrix of ciphertext with 1's");
}

template<>
Matrix<RationalCiphertext<NativePoly>>& Matrix<RationalCiphertext<NativePoly>>::Identity() {
	throw std::logic_error("Cannot create identity matrix of ciphertext");
}

template<>
Matrix<RationalCiphertext<NativePoly>> Matrix<RationalCiphertext<NativePoly>>::GadgetVector(int64_t base) const {
	throw std::logic_error("Cannot create gadget matrix of ciphertext");
}

}
