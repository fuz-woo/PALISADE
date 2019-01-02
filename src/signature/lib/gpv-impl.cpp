/**
 * @file gpv-impl.cpp Provides the GPV Ring-LWE signature scheme with trapdoors
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

// Forward definition of implementation classes for DCRT


#include "gpv.h"
#include "gpv.cpp"
#include "utils/hashutil.h"

namespace lbcrypto {

  template class GPVSignatureParameters<Poly>;
  template class GPVSignKey<Poly>;
  template class GPVVerificationKey<Poly>;
  template class GPVSignatureScheme<Poly>;
  template class GPVSignature<Poly>; 
  template class GPVPlaintext<Poly>;

  template class GPVSignatureParameters<NativePoly>;
  template class GPVSignKey<NativePoly>;
  template class GPVVerificationKey<NativePoly>;
  template class GPVSignatureScheme<NativePoly>;
  template class GPVSignature<NativePoly>; 
  template class GPVPlaintext<NativePoly>;

}
