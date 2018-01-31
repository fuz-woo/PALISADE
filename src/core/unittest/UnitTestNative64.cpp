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
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;


class UnitTestBinInt : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF BININT CLASS		*/
/************************************************/

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTNativeInteger,basic_math){

  /************************************************/
  /* TESTING METHOD PLUS FOR ALL CONDITIONS       */
  /************************************************/
  // The method "Plus" does addition on two BigIntegers a,b
  // Returns a+b, which is stored in another BigInteger
  // calculatedResult ConvertToInt converts NativeInteger
  // calculatedResult to integer

  NativeInteger calculatedResult;
  uint64_t expectedResult;
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER, NO OVERFLOW
  {
    NativeInteger a("203450");
    NativeInteger b("2034");

    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
    	<< "Failure testing Plus a_>_b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
    	<< "Failure testing + a_>_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER, NO OVERFLOW
  {
    NativeInteger a("2034");
    NativeInteger b("203450");


    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
    	<< "Failure testing Plus a_<_b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
    	<< "Failure testing + a_<_b";
  }
  // TEST CASE with overflow
  {
    NativeInteger a(((uint64_t)1)<<63);
    NativeInteger b(a);

    EXPECT_THROW(a.Plus(b), lbcrypto::math_error)
    	<< "Failure testing Plus with overflow";

    EXPECT_THROW((a+b), lbcrypto::math_error)
    	<< "Failure testing + with overflow";
  }

  /************************************************/
  /* TESTING OPERATOR += FOR ALL CONDITIONS       */
  /************************************************/

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    NativeInteger a("2034");
    NativeInteger b("203");

    a+=b;
    expectedResult = 2237;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << " Failure testing plus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    NativeInteger a("2034");
    NativeInteger b("203450");

    a+=b;
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Falure testing plus_equals_a_less_than_b";
  }
  // TEST CASE WITH OVERFLOW
  {
    NativeInteger a(((uint64_t)1)<<63);
    NativeInteger b(a);

    EXPECT_THROW((a+=b), lbcrypto::math_error)
      << "Falure testing plus_equals_overflow";
  }

  /************************************************/
  /* TESTING METHOD MINUS FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Minus" does subtraction on two BigIntegers a,b
  // Returns a-b, which is stored in another BigInteger
  // calculatedResult When a<b, the result is 0, since there is no
  // support for negative numbers as of now ConvertToInt converts
  // NativeInteger calculatedResult to integer

  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    NativeInteger a("20489");
    NativeInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    NativeInteger a("2048956567");
    NativeInteger b("2048956567");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    NativeInteger a("2048956567");
    NativeInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing minus_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    NativeInteger a("196737");
    NativeInteger b("65406");

    calculatedResult = a.Minus(b);
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing minus_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR -= FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "-=(Minus Equals)" does subtractionn of two Big
  // Integers a,b Calculates a-b, and stores result in a Results to 0,
  // when a<b, since there is no concept of negative number as of now
  // ConvertToInt converts NativeInteger a to integer
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    NativeInteger a("20489");
    NativeInteger b("2034455");

    a-=b;
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    NativeInteger a("2048956567");
    NativeInteger b("2048956567");

    a-=b;
    expectedResult = 0;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {

    NativeInteger a("2048956567");
    NativeInteger b("2034455");

    a-=b;
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Failure testing minus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    NativeInteger a("196737");
    NativeInteger b("65406");

    a-=b;
    expectedResult = 131331;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Failure testing minus_equals_borrow_from_next_byte";
  }

  /************************************************/
  /* TESTING METHOD TIMES FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Times" does multiplication on two BigIntegers
  // a,b Returns a*b, which is stored in another BigInteger
  // calculatedResult ConvertToInt converts NativeInteger
  // calculatedResult to integer
  {
    //ask about the branching if (b.m_MSB==0 or 1)
    NativeInteger a("1967");
    NativeInteger b("654");

    calculatedResult = a.Times(b);
    expectedResult = 1286418;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing times_test";
  }
  /************************************************/
  /* TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS */
  /************************************************/

  // The method "Divided By" does division of BigInteger a by
  // another BigInteger b Returns a/b, which is stored in another
  // BigInteger calculatedResult ConvertToInt converts
  // NativeInteger calculatedResult to integer When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    NativeInteger a("2048");
    NativeInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    NativeInteger a("2048956567");
    NativeInteger b("2048956567");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_equals_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    NativeInteger a("2048956567");
    NativeInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_greater_than_b";
  }


  {
	  NativeInteger a("8096");
	  NativeInteger b("4049");

	  calculatedResult = a.Mod(b);
	  expectedResult = 4047;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing Mod";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.

  {
	  NativeInteger a("8096");
	  NativeInteger b("4049");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 2;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  /*{
    NativeInteger a("204");
    NativeInteger b("210");

    calculatedResult = a.DivideAndRound(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  {
	  NativeInteger a("100");
	  NativeInteger b("210");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 0;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  /*{
    NativeInteger a("4048");
    NativeInteger b("4049");
    NativeInteger c("2");

    calculatedResult = a.MultiplyAndRound(c, b);
    expectedResult = 2;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/
}

TEST(UTNativeInteger,basic_compare){

  /************************************************/
  /* TESTING BASIC COMPARATOR METHODS AND OPERATORS */
  /**************************************************/

  /************************************************/
  /* TESTING METHOD COMPARE FOR ALL CONDITIONS    */
  /************************************************/

  // The method "Comapare" comapres two BigIntegers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as EXPECT_EQ takes integer

  int c;
  int expectedResult;

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
  {
    NativeInteger a("112504");
    NativeInteger b("46968");

    c = a.Compare(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult,c)
      << "Failure testing compare_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    NativeInteger a("12504");
    NativeInteger b("46968");

    c = a.Compare(b);
    expectedResult = -1;

    EXPECT_EQ(expectedResult,c)
      << "Failure testing compare_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    NativeInteger a("34512504");
    NativeInteger b("34512504");

    c = a.Compare(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,c)
      << "Failure testing compare_a_equals_b";
  }
}

TEST(UTNativeInteger,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigIntegers
  // m,p Returns (m mod p), which is stored in another BigInteger
  // calculatedResult ConvertToInt converts NativeInteger r to
  // integer

  NativeInteger calculatedResult;
  uint64_t expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    NativeInteger m("27");
    NativeInteger p("240");

    calculatedResult = m.Mod(p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    NativeInteger m("93409673");
    NativeInteger p("406");

    calculatedResult = m.Mod(p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    NativeInteger m("32768");
    NativeInteger p("16");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_dividible_by_modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    NativeInteger m("67108913");
    NativeInteger p("67108913");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_equal_to_modulus";
  }
}

  /************************************************/
  /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
  /************************************************/


  /* 	The method "Divided By" does division of BigInteger m by another BigInteger p
	Function takes b as argument and operates on a
  	Returns a/b, which is stored in another BigInteger calculatedResult
	ConvertToInt converts NativeInteger calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
  */



  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTNativeInteger_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    NativeInteger a("9587");
    NativeInteger b("3591");
    NativeInteger c("177");

    NativeInteger calculatedResult = a.ModBarrett(b,c);
    uint64_t expectedResult = 205484;

    std::cout<<"\n"<<d.ConvertToInt()<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult.ConvertToInt());
    }
  */
TEST(UTNativeInteger,mod_inverse){
  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on BigIntegers m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToInt converts NativeInteger calculatedResult to integer

  NativeInteger calculatedResult;
  uint64_t expectedResult;

  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    NativeInteger m("5");
    NativeInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 65;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    NativeInteger m("3017");
    NativeInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 77;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }

  //TESTCASE

  //testcase that failed during testing.
  {

    NativeInteger first("4974113608263");
    NativeInteger second("486376675628");
    string modcorrect("110346851983");
    NativeInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod regression test";


    NativeInteger input ("405107564542978792");
    NativeInteger modulus("1152921504606847009");
    string modIcorrect("844019068664266609");
    NativeInteger modIresult;

    bool thrown = false;
    try {
      modIresult = input.ModInverse(modulus);
    }
    catch (...){
      thrown = true;
    }

    EXPECT_FALSE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";
    EXPECT_EQ(modIcorrect, modIresult.ToString())
      <<"Failure ModInverse() regression test";
  }



  // Mod(0)
  {
#if 0 //BBI just hangs, do not run this test.
    NativeInteger first("4974113608263");
    NativeInteger second("0");
    string modcorrect("4974113608263");
    NativeInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod(0)";
#endif
  }


}


TEST(UTNativeInteger,mod_arithmetic){
  NativeInteger calculatedResult;
  uint64_t expectedResult;
  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    NativeInteger m("58059595");
    NativeInteger n("3768");
    NativeInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2871;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    NativeInteger m("595");
    NativeInteger n("376988");
    NativeInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 3419;

    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing second_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    NativeInteger m("595");
    NativeInteger n("376");
    NativeInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing both_numbers_less_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    NativeInteger m("59509095449");
    NativeInteger n("37654969960");
    NativeInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2861;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing both_numbers_greater_than_modulus";
  }

  {
	NativeInteger m( "4611686019217177693" );
	NativeInteger n( "2305843009213700738" );
	NativeInteger q( "4611686019217177861" );

	calculatedResult = m.ModAdd(n,q);
	expectedResult = 2305843009213700570;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing really big numbers";
  }

  {
	NativeInteger m( "13835058055282163712" );
	NativeInteger n( "13835058055282163719" );
	NativeInteger q( "13835058055282163729" );
	bool thrown = false;
	try {
	  calculatedResult = m.ModAdd(n,q);
	} catch (...) {
	  thrown = true;
	}
	
	EXPECT_FALSE(thrown) 
	  << "Failure testing ModAdd() of really big numbers threw exception ";

	expectedResult = 13835058055282163702ULL;


	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic)";
  }

  /************************************************/
  /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
  /************************************************/

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    NativeInteger m("595");
    NativeInteger n("399");
    NativeInteger q("406");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 196;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    NativeInteger m("39960");
    NativeInteger n("595090959");
    NativeInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_EQ(expectedResult,calculatedResult)
      << "Failure testing first_number_less_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    NativeInteger m("595090959");
    NativeInteger n("595090959");
    NativeInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing first_number_equals_second_number";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    NativeInteger m("595");
    NativeInteger n("376");
    NativeInteger q("4067");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 219;
    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing both_numbers_less_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    NativeInteger m("59509095449");
    NativeInteger n("37654969960");
    NativeInteger q("4067");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 3381;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing both_numbers_greater_than_modulus";
  }

  {
	NativeInteger m( "4611686019217177693" );
	NativeInteger n( "2305843009213700738" );
	NativeInteger q( "4611686019217177861" );

	calculatedResult = m.ModSub(n,q);
	expectedResult = 2305843010003476955;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing really big numbers";
  }

  {
	NativeInteger m( "13835058055282163712" );
	NativeInteger n( "13835058055282163719" );
	NativeInteger q( "13835058055282163729" );
	bool thrown = false;
	try {
	  calculatedResult = m.ModSub(n,q);
	} catch (...) {
	  thrown = true;
	}

	EXPECT_FALSE(thrown)
	  << "Failure testing ModSub() of really big numbers threw exception ";

	expectedResult = 13835058055282163722ULL;


	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic)";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  {
    NativeInteger m("39960");
    NativeInteger n("7959");
    NativeInteger q("406756");

    NativeInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 365204;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing mod_mul_test";
  }

  {
	NativeInteger m( "4611686019217177693" );
	NativeInteger n( "2305843009213700738" );
	NativeInteger q( "4611686019217177861" );

	calculatedResult = m.ModMul(n,q);
	expectedResult = 66341216340;

	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic)";
  }

  {
	NativeInteger m( "13835058055282163712" );
	NativeInteger n( "13835058055282163719" );
	NativeInteger q( "13835058055282163729" );

	calculatedResult = m.ModMul(n,q);
	expectedResult = 170;

	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic)";
  }

  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  {
    NativeInteger m("39960");
    NativeInteger n("9");
    NativeInteger q("406756");

    NativeInteger calculatedResult = m.ModExp(n,q);
    uint64_t expectedResult = 96776;

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing mod_exp_test";
  }

  {
	NativeInteger m( "4611686019217177693" );
	NativeInteger n( "2305843009213700738" );
	NativeInteger q( "4611686019217177861" );

	calculatedResult = m.ModExp(n,q);
	expectedResult = 698541107966207095;

	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic);  this test is expected to";
  }

  {
	NativeInteger m( "13835058055282163712" );
	NativeInteger n( "13835058055282163719" );
	NativeInteger q( "13835058055282163729" );

	calculatedResult = m.ModExp(n,q);
	expectedResult = 11980874853433928405ULL;

	EXPECT_EQ(expectedResult, calculatedResult)
		<< "Failure testing really super big numbers (causing overflow in 64-bit arithmetic)";
  }
}

TEST(UTNativeInteger,shift){

  /****************************/
  /* TESTING SHIFT OPERATORS  */
  /****************************/

  /*******************************************************/
  /* TESTING OPERATOR LEFT SHIFT (<<) FOR ALL CONDITIONS */
  /*******************************************************/

  // The operator 'Left Shift' operates on BigInteger a, and it
  // is shifted by a number

  // Returns: a<<(num), and the result is stored in BigIntegererger
  // calculatedResult 'a' is left shifted by 'num' number of bits, and
  // filled up by 0s from right which is equivalent to a * (2^num)
  //
  //        example:
  //            4<<3 => (100)<<3 => (100000) => 32
  //           this is equivalent to: 4* (2^3) => 4*8 =32
  //ConvertToInt converts NativeInteger calculatedResult to integer

  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39960");
    usshort shift = 3;

    NativeInteger calculatedResult = a<<(shift);
    uint64_t expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39960");
    usshort shift = 6;

    NativeInteger calculatedResult = a<<(shift);
    uint64_t expectedResult = 2557440;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_greater_than_max_shift";
  }


  /************************************************/
  /* TESTING OPERATOR LEFT SHIFT EQUALS (<<=) FOR ALL CONDITIONS -*/
  /************************************************/

  // The operator 'Left Shift Equals' operates on BigInteger a,
  // and it is shifted by a number
  // Returns:
  // a<<(num), and the result is stored in 'a'
  // 'a' is left shifted by 'num' number of bits, and filled up by 0s
  // from right which is equivalent to a * (2^num)
  // example :4<<3 => (100)<<3 => (100000) => 32
  // this is equivalent to: 4* (2^3) => 4*8 =32
  // ConvertToInt converts NativeInteger a to integer




  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39960");
    usshort num = 3;

    a<<=(num);
    uint64_t expectedResult = 319680;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39960");
    usshort num = 6;

    a<<=(num);
    uint64_t expectedResult = 2557440;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_greater_than_max_shift";
  }


  /********************************************************/
  /* TESTING OPERATOR RIGHT SHIFT (>>) FOR ALL CONDITIONS */
  /********************************************************/
  // The operator 'Right Shift' operates on BigInteger a, and it
  // is shifted by a number

  // Returns: a>>(num), and the result is stored in BigInteger
  // calculated. Result 'a' is right shifted by 'num' number of bits,
  // and filled up by 0s from left which is equivalent to a / (2^num)

  //  ex:4>>3 => (100000)>>3 => (000100) => 4

  // this is equivalent to: 32*(2^3) => 32/8 = 4
  // ConvertToInt converts NativeInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39965675");
    usshort shift = 3;

    NativeInteger calculatedResult = a>>(shift);
    uint64_t expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39965675");
    usshort shift = 6;

    NativeInteger calculatedResult = a>>(shift);
    uint64_t expectedResult = 624463;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_greater_than_max_shift";
  }


  /***************************************************************/
  /* TESTING OPERATOR RIGHT SHIFT EQUALS(>>=) FOR ALL CONDITIONS */
  /***************************************************************/

  // The operator 'Right Shift Equals' operates on BigInteger a,
  // and it is shifted by a number

  // Returns: a>>=(num), and the result is stored in a 'a' is right
  // shifted by 'num' number of bits, and filled up by 0s from left
  // which is equivalent to a / (2^num)

  //   ex:4>>3 => (100000)>>3 => (000100) => 4

  //   this is equivalent to: 32*(2^3) => 32/8 = 4
  //   ConvertToInt converts NativeInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39965675");
    usshort shift = 3;

    a>>=(shift);
    uint64_t expectedResult = 4995709;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    NativeInteger a("39965675");
    usshort shift = 6;

    a>>=(shift);
    uint64_t expectedResult = 624463;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_greater_than_max_shift";
  }
}

/****************************************/
/* TESTING METHOD  BitStringToBigInteger */
/****************************************/

TEST(UTNativeInteger,method_binary_string_to_big_binary_integer){
	//TEST CASE FOR STATIC METHOD BitStringToBigInteger in NativeInteger

	string binaryString = "1011101101110001111010111011000000011";
	NativeInteger b =
			NativeInteger::BitStringToBigInteger(binaryString);

	NativeInteger expectedResult("100633769475");
	EXPECT_EQ(expectedResult, b)
	<< "Failure testing BitStringToBigInteger";
}

/****************************************/
/* TESTING METHOD  EXP                  */
/****************************************/
TEST(UTNativeInteger,method_exponentiation_without_modulus){

  NativeInteger x("56");
  NativeInteger result = x.Exp(10);

  NativeInteger expectedResult("303305489096114176");
  EXPECT_EQ(expectedResult, result)
    << "Failure testing exp";
}

TEST(UTNativeInteger,method_ConvertToDouble) {
  NativeInteger x("104037585658683683");
  double xInDouble = 104037585658683683;

  EXPECT_EQ(xInDouble, x.ConvertToDouble());
}
