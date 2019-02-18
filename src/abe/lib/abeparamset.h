/**
 * @file abeparamset.h - Parameter sets for ABE schemes
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
#ifndef ABE_PARAMS_SET_H
#define ABE_PARAMS_SET_H
#include "lattice/stdlatticeparms.h"
namespace lbcrypto{
//Map holding minimum ring size and appropriate base in IBE for the given security level
static std::map<SecurityLevel,std::pair<usint,usint>> IBEMinRingSizeMap = {
    {HEStd_128_classic,{1024,2}},
    {HEStd_192_classic,{2048,512}},
    {HEStd_256_classic,{2048,2}}
};

//Map holding minimum ring size and base in CPABE for the given security level and number of attributes
static std::map<std::pair<SecurityLevel,usint>,std::pair<usint,usint>> CPABEMinRingSizeMap = {
    {{HEStd_128_classic,6},{1024,2}},
    {{HEStd_128_classic,8},{1024,2}},
    {{HEStd_128_classic,16},{1024,2}},
    {{HEStd_128_classic,20},{1024,2}},
    {{HEStd_128_classic,32},{1024,2}},
    {{HEStd_192_classic,6},{2048,128}},
    {{HEStd_192_classic,8},{2048,128}},
    {{HEStd_192_classic,16},{2048,128}},
    {{HEStd_192_classic,20},{2048,128}},
    {{HEStd_192_classic,32},{2048,128}},
    {{HEStd_256_classic,6},{2048,2}},
    {{HEStd_256_classic,8},{2048,2}},
    {{HEStd_256_classic,16},{2048,2}},
    {{HEStd_256_classic,20},{2048,2}},
    {{HEStd_256_classic,32},{2048,2}},
};
}
#endif