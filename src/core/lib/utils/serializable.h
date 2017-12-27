/**
 * @file serializable.h Serialization utilities.
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
#ifndef LBCRYPTO_SERIALIZABLE_H
#define LBCRYPTO_SERIALIZABLE_H
#include <vector>
#include <unordered_map>
#include <sstream>
#include <string>
#include <iomanip>
#ifndef RAPIDJSON_HAS_STDSTRING
#define RAPIDJSON_HAS_STDSTRING
#endif
#ifndef RAPIDJSON_HAS_CXX11_RVALUE_REFS
#define RAPIDJSON_HAS_CXX11_RVALUE_REFS
#endif
#include "rapidjson/document.h"
#include "rapidjson/pointer.h"
#include "rapidjson/reader.h"
#include "rapidjson/error/en.h"

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

	// C+11 "using" is not supported in VS 2012 - so it was replaced with C+03 "typedef"
	typedef rapidjson::Value SerialItem;
	typedef rapidjson::Document Serialized;

	//using SerialItem = rapidjson::Value;
	//using Serialized = rapidjson::Document;

	class Serializable
	{
		/**
		* Version number of the serialization; defaults to 1
		* @return version of the serialization
		*/
		virtual int getVersion() { return 1; }

	public:
		virtual ~Serializable() {}

		/**
		* Serialize the object into a Serialized
		* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		* @return true if successfully serialized
		*/
		virtual bool Serialize(Serialized* serObj) const = 0;

		/**
		 * SerializeWithoutContext serializes the object but does NOT include the context -
		 * used in places where the object is included in a context
		 *
		 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
		 * @return true if successfully serialized
		 */
		virtual bool SerializeWithoutContext(Serialized* serObj) const {
			return Serialize(serObj);
		}

		/**
		* Populate the object from the deserialization of the Serialized
		* @param serObj contains the serialized object
		* @return true on success
		*/
		virtual bool Deserialize(const Serialized& serObj) = 0;
	};

//helper template to stream vector contents provided T has an stream operator<< 
template < typename T >
std::ostream& operator << (std::ostream& os, const std::vector<T>& v)
{
    os << "[";
    for (auto i = v.begin(); i!= v.end(); ++i){
      os << " " << *i;
    }
    os << " ]";
    return os;
 };

}

#endif
