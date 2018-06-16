/**
 * @file quadfloat.cpp This file has the definitions for the quad-precision floating-point data type
 *
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

#include "quadfloat.h"

namespace lbcrypto {

const QuadFloat HALF_QUADFLOAT = quadFloatFromInt64(1)/quadFloatFromInt64(2);

//static void normalize(QuadFloat& z, const double& xhi, const double& xlo);

int64_t quadFloatRound(const QuadFloat& input)
{
   double fhi, flo;

   // since the rounding is implemented using floor, we add 0.5
   QuadFloat x = input + HALF_QUADFLOAT;

   fhi = floor(x.hi);

   if (fhi == x.hi)
      flo = floor(x.lo);
   else
      flo = 0;

   // the following code helps to prevent unnecessary integer overflow,
   // and guarantees that to_long(to_quad_float(a)) == a, for all long a,
   // provided long's are not too wide.

   if (fhi > 0)
      return int64_t(flo) - int64_t(-fhi);
   else
      return int64_t(fhi) + int64_t(flo);
}

QuadFloat quadFloatFromInt64(const long long int n){

   double xhi, xlo;

   xhi = NTL::TrueDouble(n);

   // Because we are assuming 2's compliment integer
   // arithmetic, the following prevents (long long)(xhi) from overflowing.

   //if (n > 0)
	  xlo = NTL::TrueDouble(n+(long long)(-xhi));
   //else
   //	  xlo = NTL::TrueDouble(n-(long long)(xhi));

   // renormalize...just to be safe

   //QuadFloat z;
   //normalize(z, xhi, xlo);
   //return z;

   return NTL::quad_float(xhi,xlo);

}

/*static void normalize(QuadFloat& z, const double& xhi, const double& xlo){

   double u, v;

   u = xhi + xlo;
   v = xhi - u;
   v = v + xlo;

   z.hi = u;
   z.lo = v;

}*/

} // namespace lbcrypto ends
