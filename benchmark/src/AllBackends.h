/*
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

// this file contains the magic needed to compile and benchmark all backends in the same executable

#ifndef BENCHMARK_SRC_ALLBACKENDS_H_
#define BENCHMARK_SRC_ALLBACKENDS_H_

#define _USE_MATH_DEFINES
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "lattice/dcrtpoly.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

using BE2Integer = cpu_int::BigInteger<integral_dtype,BigIntegerBitLength>;
using BE2ILParams = ILParamsImpl<BE2Integer>;
using BE2ILDCRTParams = ILDCRTParams<BE2Integer>;
using BE2Vector = cpu_int::BigVectorImpl<BE2Integer>;
using BE2Poly = PolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILParams>;
using BE2DCRTPoly = DCRTPolyImpl<BE2Integer, BE2Integer, BE2Vector, BE2ILDCRTParams>;

using BE4Integer = exp_int::xubint;
using BE4ILParams = ILParamsImpl<BE4Integer>;
using BE4ILDCRTParams = ILDCRTParams<BE4Integer>;
using BE4Vector = exp_int::xmubintvec;
using BE4Poly = PolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILParams>;
using BE4DCRTPoly = DCRTPolyImpl<BE4Integer, BE4Integer, BE4Vector, BE4ILDCRTParams>;

using BE6Integer = NTL::myZZ;
using BE6ILParams = ILParamsImpl<BE6Integer>;
using BE6ILDCRTParams = ILDCRTParams<BE6Integer>;
using BE6Vector = NTL::myVecP<NTL::myZZ>;
using BE6Poly = PolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILParams>;
using BE6DCRTPoly = DCRTPolyImpl<BE6Integer, BE6Integer, BE6Vector, BE6ILDCRTParams>;

#endif /* BENCHMARK_SRC_ALLBACKENDS_H_ */
