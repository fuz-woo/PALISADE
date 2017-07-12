/*
 * @file 
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
 /*
	This code exercises the math libraries of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "utils/utilities.h"
#include "utils/debug.h"

using namespace std;
using namespace lbcrypto;

/*
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
*/


/*
EXPECT_EQ (expected, actual) verifies expected == actual.
Compares two integer values
*/





/*---------------------------------------	TESTING METHODS OF BINVECT CLASS		--------------------------------------------*/



//---------------------TESTING INTEGER OPERATIONS ON VECTOR---------------------------------//

/*
	GetValAtIndex() operates on Big Vector, retrieves the value at the given index of a vector
	The functions returns BigIntegererger, which is passed to ConvertToInt() to convert to integer
	One dimensional integer array expectedResult is created
	Indivdual expected result for each index of the vector is store in array
	EXPECT_EQ is given the above integer from GetValAtIndex, and the value of the expectedResult at the corresponding index
*/





/*--------------TESTING METHOD MODULUS FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod" operates on Big Vector m, BigInteger q
  	Returns:  m mod q, and the result is stored in Big Vector calculatedResult.
*/
TEST(UTBinVect, SetModulusTest){

	BigVector m(10);
	
	m.SetValAtIndex(0,"987968");
	m.SetValAtIndex(1,"587679");
	m.SetValAtIndex(2,"456454");
	m.SetValAtIndex(3,"234343");
	m.SetValAtIndex(4,"769789");
	m.SetValAtIndex(5,"465654");
	m.SetValAtIndex(6,"79");
	m.SetValAtIndex(7,"346346");
	m.SetValAtIndex(8,"325328");
	m.SetValAtIndex(9,"7698798");	

	BigInteger q("233");

	m.SetModulus(q);

	BigVector calculatedResult = m.Mod(q);

	uint64_t expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}

}


TEST(UTBinVect,NTL_modulus_framework){
#if MATHBACKEND  == 6 //NTL backend

  bool dbg_flag = true;

  //code to test that the modulus framwork is ok

  NTL::myZZ q1("1234567"); // a bigger number
  NTL::myZZ q2("345"); // a smaller bigger number

  NTL::myVecP<NTL::myZZ_p>  m(5); 
  m = {"9868", "5879", "4554", "2343", "4624",}; 
  vector<usint> m_expected_1 = {9868, 5879, 4554, 2343, 4624,}; 

  m.SetModulus(q1);

  //test the modulus of the entire vector.
  NTL::myZZ qtest1 = m.GetModulus();
  DEBUG("m "<<m);
  DEBUG("q1 "<<q1);
  DEBUG("qtest1 "<<qtest1);
  EXPECT_EQ(q1, qtest1)<<"Failure NTL vector.GetModulus() 1";

  for (size_t i = 0; i < m.size(); i++){
    EXPECT_EQ(m_expected_1[i],m[i]) << "Failure in NTL ["<<i<<"]";
  }
  NTL::myZZ_p elem = m[0]; //should inheret the modulus.

  EXPECT_EQ(9868U,elem) << "Failure in NTL elem 1";
  EXPECT_EQ(qtest1,elem.GetModulus()) << "Failure in NTL elem.GetModulus() 1";

  //now switch the modulus.
  m.SetModulus(q2);

  //test the modulus of the entire vector.
  NTL::myZZ qtest2 = m.GetModulus();
  DEBUG("m "<<m);
  DEBUG("q2 "<<q2);
  DEBUG("qtest2 "<<qtest2);
  vector<usint> m_expected_2 = {208, 14, 69, 273, 139,}; 
  EXPECT_EQ(q2, qtest2)<<"Failure NTL vector.GetModulus() 2";

  for (size_t i = 0; i < m.size(); i++){
    EXPECT_EQ(m_expected_2[i],m[i]) << "Failure in NTL ["<<i<<"]";
  }

  NTL::myZZ_p elem2 = m[0];

  EXPECT_EQ(208U,elem2) << "Failure in NTL elem";
  EXPECT_EQ(qtest2,elem2.GetModulus()) << "Failure in NTL elem.GetModulus()";
 
  EXPECT_NE(elem.GetModulus(), elem2.GetModulus())
    << "Failure in NTL compare moduli()";

#endif
}

TEST(UTBinVect, CTOR_Test){
  const usint len  = 10;
  BigInteger q("233");
  usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};

  {
    BigVector m(len, q, 
		    {"987968","587679","456454","234343",
			"769789","465654","79","346346",
			"325328","7698798"});	

    BigVector calculatedResult = m.Mod(q);


    for (usint i=0;i<len;i++){
      EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
    }
  }

  {
    BigVector m(len, q,  {48,53,7,178,190,120,79,108,60,12});

    for (usint i=0;i<len;i++){
      EXPECT_EQ (expectedResult[i], m.GetValAtIndex(i).ConvertToInt());
    }

  }
}


/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector calculatedResult.
*/

// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

TEST(UTBinVect,ModAddBBITestBigModulus){

	BigInteger q("3435435");	// constructor calling to set mod value
	BigVector m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("3");

	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	BigVector calculatedResult = m.ModAdd(n);

	uint64_t expectedResult[5] = {9871, 5882,4557,2346,9792};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}

}


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

TEST(UTBinVect,ModAddBBITestSmallerModulus){
  bool dbg_flag = false;

	BigInteger q("3534");	// constructor calling to set mod value
	BigVector m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("34365");

	DEBUG("m's modulus "<<m.GetModulus());
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigVector calculatedResult = m.ModAdd(n);

	DEBUG("m "<<m);
	DEBUG("calculated result  "<< calculatedResult);
	uint64_t expectedResult[5] = {1825,1370,45,1368,1746};
	
	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}


/*--------------TESTING METHOD MODUSUB FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Sub" operates on Big Vector m, BigIntegers n,q
  	Returns:  
		when m>n, (m-n)mod q
		when m=n, 0 
		when m<n, {(m mod q)+q-(n mod q)} mod q
	and the result is stored in Big Vector calculatedResult.
*/

// TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER 

TEST(UTBinVect,modsub_first_number_less_than_second_number){

	BigInteger q("3534");			// constructor calling to set mod value
	BigVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("34365");

	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigVector calculatedResult = m.ModSub(n);

	uint64_t expectedResult[5] = {241,3320,1995,3318,162};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}

// TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER 

TEST(UTBinVect,modsub_first_number_greater_than_second_number){

	BigInteger q("35");	// constructor calling to set mod value
	BigVector m(5,q);		// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("765");
	
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");
	
	BigVector calculatedResult = m.ModSub(n);

	uint64_t expectedResult[5] = {3,4,9,3,29};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}


/*--------------TESTING METHOD MODUMUL FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Mod" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m*n)mod q
	and the result is stored in Big Vector calculatedResult.
*/
TEST(UTBinVect,test_modmul_BBI){

	BigInteger q("3534");			// constructor calling to set mod value
	BigVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("46");

	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	BigVector calculatedResult = m.ModMul(n);

	uint64_t expectedResult[5] = {1576,1850,978,1758,1476};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}



/*--------------TESTING METHOD MODEXP FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Exp" operates on Big Vector m, BigIntegers n,q
  	Returns:  (m^n)mod q
	and the result is stored in Big Vector calculatedResult.
*/
TEST(UTBinVect,test_modexp){
  bool dbg_flag = false;
	BigInteger q("3534");			// constructor calling to set mod value
	BigVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q
	BigInteger n("3");

	m.SetValAtIndex(0,"968");
	m.SetValAtIndex(1,"579");
	m.SetValAtIndex(2,"4");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"97");
	DEBUG("m's modulus "<<m.GetModulus());
	
	BigVector calculatedResult = m.ModExp(n);

	uint64_t expectedResult[5] = {2792,3123,64,159,901};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}


/*--------------TESTING METHOD MODINVERSE FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod ModInverse" operates on Big Vector m, BigInteger q
  	Returns:  (m^(-1))mod q
		when m and q are co-prime (i,e GCD of m and q is 1)
		and is calculated using extended Eucleadian Algorithm
	and the result is stored in Big Vector calculatedResult.
*/
TEST(UTBinVect,test_modinv){

	BigInteger q("35");			// constructor calling to set mod value
	BigVector m(5,q);				// calling constructor to create a vector of length 5 and passing value of q

	m.SetValAtIndex(0,"968");
	m.SetValAtIndex(1,"579");
	m.SetValAtIndex(2,"4");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"97");
	
	BigVector calculatedResult = m.ModInverse();

	uint64_t expectedResult[5] = {32,24,9,17,13};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}

}

/*--------------TESTING METHOD MODADD FOR ALL CONDITIONS---------------------------*/

/* 	The method "Mod Add" operates on Big Vectors m,n BigInteger q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector calculatedResult.
*/


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE SMALLER THAN MODULUS 

TEST(UTBinVect, modadd_vector_result_smaller_modulus){
		
	BigInteger q("878870");		// constructor calling to set mod value
	BigVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigVector n(5,q);

	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	n.SetValAtIndex(0,"4533");
	n.SetValAtIndex(1,"4549");
	n.SetValAtIndex(2,"6756");
	n.SetValAtIndex(3,"1233");
	n.SetValAtIndex(4,"7897");
	
	BigVector calculatedResult = m.ModAdd(n);

	uint64_t expectedResult[5] = {14401,10428,11310,3576,17686};

	for (usint i=0;i<5;i++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}


// TEST CASE WHEN NUMBERS AFTER ADDITION ARE GREATER THAN MODULUS 

TEST(UTBinVect, modadd_vector_result_greater_modulus){

	BigInteger q("657");		// constructor calling to set mod value
	BigVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigVector n(5,q);	
	
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	n.SetValAtIndex(0,"4533");
	n.SetValAtIndex(1,"4549");
	n.SetValAtIndex(2,"6756");
	n.SetValAtIndex(3,"1233");
	n.SetValAtIndex(4,"7897");
	
	BigVector calculatedResult = m.ModAdd(n);

	uint64_t expectedResult[5] = {604,573,141,291,604};

	for (usint i=0;i<5;i++)
	{
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}

}


/*--------------TESTING METHOD PLUS EQUALS FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Plus Equals" operates on Big Vectors m,n BigInteger q
  	Returns:  (m+n)mod q, and the result is stored in Big Vector a.
*/
TEST(UTBinVect,method_plus_equals_vector_operation){
	BigInteger q("657");	
	BigVector m(5,q); // calling constructor to create a vector of length 5 and passing value of q
	BigVector n(5,q);
	
	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	n.SetValAtIndex(0,"4");
	n.SetValAtIndex(1,"9");
	n.SetValAtIndex(2,"66");
	n.SetValAtIndex(3,"33");
	n.SetValAtIndex(4,"7");

	m+=n;

	uint64_t expectedResult[5] = {17,632,21,405,598};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (m.GetValAtIndex(i)).ConvertToInt());
	}
}


/*--------------TESTING METHOD MODMUL FOR ALL CONDITIONS---------------------------*/

/* 	The operator "Mod Mul" operates on Big Vectors m,n BigInteger q
  	Returns:  (m*n)mod q, and the result is stored in Big Vector a.
*/

TEST(UTBinVect, modmul_vector){

	BigInteger q("657");		// constructor calling to set mod value
	BigVector m(5,q);			// calling constructor to create a vector of length 5 and passing value of q
	BigVector n(5,q);

	m.SetValAtIndex(0,"9868");
	m.SetValAtIndex(1,"5879");
	m.SetValAtIndex(2,"4554");
	m.SetValAtIndex(3,"2343");
	m.SetValAtIndex(4,"9789");

	n.SetValAtIndex(0,"4");
	n.SetValAtIndex(1,"9");
	n.SetValAtIndex(2,"66");
	n.SetValAtIndex(3,"33");
	n.SetValAtIndex(4,"7");
	
	BigVector calculatedResult = m.ModMul(n);

	uint64_t expectedResult[5] = {52,351,315,450,195};

	for (usint i=0;i<5;i++){
		EXPECT_EQ (expectedResult[i], (calculatedResult.GetValAtIndex(i)).ConvertToInt());
	}
}
