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
#include "math/discretegaussiangenerator.h"
#include "utils/debug.h"
//#include <vld.h>
using namespace lbcrypto;

int main() {
	double std = 10000;
	DiscreteGaussianGenerator dgg(std);
	double start, finish;

	size_t count = 100000;

	start = currentDateTime();
	dgg.GenerateProbMatrix(std, 0);
	finish = currentDateTime();
	std::cout << "Probability matrix generation: " << finish - start << " ms\n";

	start = currentDateTime();
	for (size_t i = 0;i < count;i++) {
		dgg.GenerateInteger(0, std, 1024);
	}
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Rejection): " << finish - start << " ms\n";

	start = currentDateTime();
	for (size_t i = 0;i < count;i++) {
		//dgg.GenerateIntegerKnuthYao();
	}
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Knuth-Yao): " << finish - start << " ms\n";

	start = currentDateTime();
	dgg.GenerateIntVector(count);
	finish = currentDateTime();
	std::cout << "Sampling 100000 integers (Peikert): " << finish - start << " ms\n";

	std::cin.ignore();
	std::cin.get();
	return 0;
}
