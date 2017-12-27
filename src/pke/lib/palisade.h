/**
 * @file palisade.h -- PALISADE.
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

#ifndef SRC_LIB_PALISADE_H_
#define SRC_LIB_PALISADE_H_

#include <initializer_list>

#include <string>
using std::string;

#include <memory>
using std::shared_ptr;

#include <utility>
using std::move;

namespace lbcrypto {

template<typename Element>
class CryptoContextImpl;

template<typename Element>
using CryptoContext = shared_ptr<CryptoContextImpl<Element>>;

template<typename Element>
class CiphertextImpl;

template<typename Element>
using Ciphertext = shared_ptr<CiphertextImpl<Element>>;

}

#include "math/backend.h"
#include "math/distrgen.h"
#include "math/matrix.h"

#include "utils/inttypes.h"
#include "utils/exception.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "../../core/lib/lattice/dcrtpoly.h"

#include "encoding/encodings.h"

#include "pubkeylp.h"

#include "rlwe.h"
#include "ltv.h"
#include "stst.h"
#include "bgv.h"
#include "bfv.h"
#include "bfvrns.h"
#include "nullscheme.h"

#include "utils/serializable.h"

#include "ciphertext.h"
#include "rationalciphertext.h"



#endif /* SRC_LIB_PALISADE_H_ */
