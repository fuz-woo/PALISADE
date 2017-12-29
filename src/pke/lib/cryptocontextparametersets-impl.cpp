/*
* @file cryptocontextparametersets-impl.cpp - cryptocontext parameter sets implementation
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

#include "cryptocontextparametersets.h"

namespace lbcrypto {

map<string, map<string,string>> CryptoContextParameterSets = {

		{ "LTV1" , {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "268441601" },
				{ "rootOfUnity", "16947867" },
				{ "relinWindow", "1" },
				{ "stDev", "4" }
		} },

		{ "LTV2", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "536881153" },
				{ "rootOfUnity", "267934765" },
				{ "relinWindow", "2" },
				{ "stDev", "4" }
		} },

		{ "LTV3", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "1073750017" },
				{ "rootOfUnity", "180790047" },
				{ "relinWindow", "4" },
				{ "stDev", "4" }
		} },

		{ "LTV4", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "2678760785" },
				{ "relinWindow", "8" },
				{ "stDev", "4" }
		} },

		{ "LTV5", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "4096" },
				{ "modulus", "2199023288321" },
				{ "rootOfUnity", "1858080237421" },
				{ "relinWindow", "16" },
				{ "stDev", "4" }
		} },

		{ "StSt1", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "8451304774" },
				{ "relinWindow", "1" },
				{ "stDev", "4" },
				{ "stDevStSt", "98.4359" }
		} },

		{ "StSt2", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "137439004673" },
				{ "rootOfUnity", "7643730114" },
				{ "relinWindow", "8" },
				{ "stDev", "4" },
				{ "stDevStSt", "214.9" }
		} },

		{ "StSt3", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring",  "4096" },
				{ "modulus", "17179926529" },
				{ "rootOfUnity", "1874048014" },
				{ "relinWindow", "1" },
				{ "stDev", "4" },
				{ "stDevStSt", "98.4359" }
		} },

		{ "StSt4", {
				{ "Note", "FGCS1" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring", "4096" },
				{ "modulus", "140737488486401" },
				{ "rootOfUnity", "65185722416667" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "354.34" }
		} },

		{ "StSt5", {
				{ "Note", "FGCS2" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "16" },
				{ "ring", "4096" },
				{ "modulus", "72057594037948417" },
				{ "rootOfUnity", "12746853818308484" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "1511.83" }
		} },

		{ "StSt6", {
				{ "Note", "FGCS Final" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "256" },
				{ "ring", "8192" },
				{ "modulus", "75557863725914323468289" },
				{ "rootOfUnity", "36933905409054618621009" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "41411.5" }
		} },

		{ "BFV1", {
				{ "parameters", "BFV" },
				{ "plaintextModulus", "4" },
				{ "securityLevel", "1.006" },
		} },

		{ "BFV2", {
				{ "parameters", "BFV" },
				{ "plaintextModulus", "16" },
				{ "securityLevel", "1.006" }
		} },

		{ "BFVrns1", {
				{ "parameters", "BFVrns" },
				{ "plaintextModulus", "4" },
				{ "securityLevel", "1.006" },
		} },

		{ "BFVrns2", {
				{ "parameters", "BFVrns" },
				{ "plaintextModulus", "16" },
				{ "securityLevel", "1.006" }
		} },

		{ "BGV1", {
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "268441601" },
				{ "rootOfUnity", "16947867" },
				{ "relinWindow", "1" },
				{ "stDev", "4" },
		} },

		{ "BGV2", {
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "536881153" },
				{ "rootOfUnity", "267934765" },
				{ "relinWindow", "2" },
				{ "stDev", "4" },
		} },

		{ "BGV3", {
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "1073750017" },
				{ "rootOfUnity", "180790047" },
				{ "relinWindow", "4" },
				{ "stDev", "4" },
		} },

		{ "BGV4", {
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "2678760785" },
				{ "relinWindow", "8" },
				{ "stDev", "4" },
		} },

		{ "BGV5", {
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "4096" },
				{ "modulus", "2199023288321" },
				{ "rootOfUnity", "1858080237421" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
		} },

		{ "Null", {
				{ "parameters", "Null" },
				{ "plaintextModulus", "256" },
				{ "ring", "8192" },
				{ "modulus", "256" },
				{ "rootOfUnity", "242542334" }
		} },

		{ "Null2", {
				{ "parameters", "Null" },
				{ "plaintextModulus", "5" },
				{ "ring", "32" },
				{ "modulus", "256" },
				{ "rootOfUnity", "322299632" }
		} },
		{ "LTV-PRE" ,{
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "2678760785" },
				{ "relinWindow", "8" },
				{ "stDev", "4" }
		} },
		{ "StSt-PRE",{
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "137439004673" },
				{ "rootOfUnity", "7643730114" },
				{ "relinWindow", "8" },
				{ "stDev", "4" },
				{ "stDevStSt", "214.9" }
		} },
		{ "BFV-PRE",{
				{ "parameters", "BFV" },
				{ "plaintextModulus", "2" },
				{ "securityLevel", "1.006" }
		} },
		{ "BGV-PRE",{
				{ "parameters", "BGV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "2678760785" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
		} },
		{ "Null-PRE",{
				{ "parameters", "Null" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "2" },
				{ "rootOfUnity", "1" }
		} }

};

} /* namespace lbcrypto */
