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

#define PROFILE
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

inline void identity_test(BigInteger& a) {
	BigInteger ZERO(0);
	BigInteger ONE(1);

	EXPECT_EQ(a, a + ZERO) << "Failure testing a + 0";
	EXPECT_EQ(a, a += ZERO) << "Failure testing a += 0";
	EXPECT_EQ(a, a * ONE) << "Failure testing a * 1";
	EXPECT_EQ(a, a *= ONE) << "Failure testing a *= 1";

	EXPECT_EQ(a, ZERO + a) << "Failure testing 0 + a";
	EXPECT_EQ(a, ZERO += a) << "Failure testing 0 += a";
	EXPECT_EQ(a, ONE * a) << "Failure testing 1 * a";
	EXPECT_EQ(a, ONE *= a) << "Failure testing 1 *= a";

	EXPECT_EQ(a*a, ONE *= a) << "Failure on 1 *= a, twice";
}

TEST(UTBinInt,identity) {
	BigInteger sm("3279");
	BigInteger lg("1234567898765432");

	identity_test( sm );
	identity_test( lg );
}

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTBinInt,basic_math){

  /************************************************/
  /* TESTING METHOD PLUS FOR ALL CONDITIONS       */
  /************************************************/
  // The method "Plus" does addition on two BigIntegers a,b
  // Returns a+b, which is stored in another BigInteger
  // calculatedResult ConvertToInt converts BigInteger
  // calculatedResult to integer

  BigInteger calculatedResult;
  uint64_t expectedResult;
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    BigInteger a("203450");
    BigInteger b("2034");

    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing plus_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    BigInteger a("2034");
    BigInteger b("203450");


    calculatedResult = a.Plus(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing plus_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    BigInteger a("768900");
    BigInteger b("16523408");

    calculatedResult = a.Plus(b);
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    BigInteger a("35");
    BigInteger b("1015");

    calculatedResult = a.Plus(b);
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing plus_no_overflow_to_next_byte";
  }

  /************************************************/
  /* TESTING OPERATOR += FOR ALL CONDITIONS       */
  /************************************************/

  // The operator "+=(Plus Equals)" does addition of two Big
  // Integers a,b Calculates a+b, and stores result in a ConvertToInt
  // converts BigInteger a to integer


  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    BigInteger a("2034");
    BigInteger b("203");

    a+=b;
    expectedResult = 2237;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << " Failure testing plus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    BigInteger a("2034");
    BigInteger b("203450");

    a+=b;
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Falure testing plus_equals_a_less_than_b";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // BYTE
  {
    BigInteger a("768900");
    BigInteger b("16523408");

    a+=b;
    expectedResult = 17292308;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Falure testing plus_equals_overflow_to_next_byte";
  }
  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW IN THE SAME
  // BYTE
  {
    BigInteger a("35");
    BigInteger b("1015");

    a+=b;
    expectedResult = 1050;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Falure testing plus_equals_no_overflow_to_next_byte";
  }
  /************************************************/
  /* TESTING METHOD MINUS FOR ALL CONDITIONS      */
  /************************************************/

  // The method "Minus" does subtraction on two BigIntegers a,b
  // Returns a-b, which is stored in another BigInteger
  // calculatedResult When a<b, the result is 0, since there is no
  // support for negative numbers as of now ConvertToInt converts
  // BigInteger calculatedResult to integer

  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    BigInteger a("20489");
    BigInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    BigInteger a("2048956567");
    BigInteger b("2048956567");

    calculatedResult = a.Minus(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing minus_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    BigInteger a("2048956567");
    BigInteger b("2034455");

    calculatedResult = a.Minus(b);
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing minus_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    BigInteger a("196737");
    BigInteger b("65406");

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
  // ConvertToInt converts BigInteger a to integer
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER

    BigInteger a("20489");
    BigInteger b("2034455");

    a-=b;
    expectedResult = 0;

    //SINCE THERE IS NO CONCEPT OF NEGATIVE NUMEBR RESULT SHOULD BE
    //ZERO
    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    BigInteger a("2048956567");
    BigInteger b("2048956567");

    a-=b;
    expectedResult = 0;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing minus_equals_a_equal_to_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {

    BigInteger a("2048956567");
    BigInteger b("2034455");

    a-=b;
    expectedResult = 2046922112;

    EXPECT_EQ(expectedResult,a.ConvertToInt())
      << "Failure testing minus_equals_a_greater_than_b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    BigInteger a("196737");
    BigInteger b("65406");

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
  // calculatedResult ConvertToInt converts BigInteger
  // calculatedResult to integer
  {
    //ask about the branching if (b.m_MSB==0 or 1)
    BigInteger a("1967");
    BigInteger b("654");

    calculatedResult = a*b;
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
  // BigInteger calculatedResult to integer When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    BigInteger a("2048");
    BigInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_less_than_b";
  }

  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    BigInteger a("2048956567");
    BigInteger b("2048956567");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_equals_b";
  }

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    BigInteger a("2048956567");
    BigInteger b("2034455");

    calculatedResult = a.DividedBy(b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing divided_by_a_greater_than_b";
  }

  {
	  BigInteger a("8096");
	  BigInteger b("4049");

	  calculatedResult = a.Mod(b);
	  expectedResult = 4047;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing Mod";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.

  {
	  BigInteger a("8096");
	  BigInteger b("4049");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 2;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  /*{
    BigInteger a("204");
    BigInteger b("210");

    calculatedResult = a.DivideAndRound(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  {
	  BigInteger a("100");
	  BigInteger b("210");

	  calculatedResult = a.DivideAndRound(b);
	  expectedResult = 0;

	  EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
		  << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/

  // TEST CASE FOR VERIFICATION OF ROUNDING OPERATION.
  /*{
    BigInteger a("4048");
    BigInteger b("4049");
    BigInteger c("2");

    calculatedResult = a.MultiplyAndRound(c, b);
    expectedResult = 2;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing divided_and_rounding_by_a_greater_than_b";
  }*/
}

TEST(UTBinInt,basic_compare){

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
    BigInteger a("112504");
    BigInteger b("46968");

    c = a.Compare(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_greater_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    BigInteger a("12504");
    BigInteger b("46968");

    c = a.Compare(b);
    expectedResult = -1;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_less_than_b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    BigInteger a("34512504");
    BigInteger b("34512504");

    c = a.Compare(b);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,(int)c)
      << "Failure testing compare_a_equals_b";
  }
}

TEST(UTBinInt,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two BigIntegers
  // m,p Returns (m mod p), which is stored in another BigInteger
  // calculatedResult ConvertToInt converts BigInteger r to
  // integer

  BigInteger calculatedResult;
  uint64_t expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    BigInteger m("27");
    BigInteger p("240");

    calculatedResult = m.Mod(p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    BigInteger m("93409673");
    BigInteger p("406");

    calculatedResult = m.Mod(p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    BigInteger m("32768");
    BigInteger p("16");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_dividible_by_modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    BigInteger m("67108913");
    BigInteger p("67108913");

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
	ConvertToInt converts BigInteger calculatedResult to integer
	When b=0, throws error, since division by Zero is not allowed
	When a<b, returns 0, since decimal value is not returned
  */



  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTBinInt_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    BigInteger a("9587");
    BigInteger b("3591");
    BigInteger c("177");

    BigInteger calculatedResult = a.ModBarrett(b,c);
    int expectedResult = 205484;

    std::cout<<"\n"<<d.ConvertToInt()<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult.ConvertToInt());
    }
  */
TEST(UTBinInt,mod_inverse){
  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on BigIntegers m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToInt converts BigInteger calculatedResult to integer

  BigInteger calculatedResult;
  uint64_t expectedResult;

  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    BigInteger m("5");
    BigInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 65;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_less_than_modulus";
  }
  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    BigInteger m("3017");
    BigInteger p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 77;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing number_greater_than_modulus";
  }

  //TESTCASE 

  //testcase that failed during testing.
  {

    BigInteger first("4974113608263");
    BigInteger second("486376675628");
    string modcorrect("110346851983");
    BigInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod regression test";


    BigInteger input ("405107564542978792");
    BigInteger modulus("1152921504606847009");
    string modIcorrect("844019068664266609");
    BigInteger modIresult;

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
    BigInteger first("4974113608263");
    BigInteger second("0");
    string modcorrect("4974113608263");
    BigInteger modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult.ToString())
      <<"Failure ModInverse() Mod(0)";
#endif
  }


}


TEST(UTBinInt,mod_arithmetic){
  BigInteger calculatedResult;
  uint64_t expectedResult;
  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/
  // The method "Mod Add" operates on BigIntegers m,n,q
  //   Returns:
  //     (m+n)mod q
  //      = {(m mod q) + (n mod q)}mod q
  //   ConvertToInt converts BigInteger calculatedResult to integer

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    BigInteger m("58059595");
    BigInteger n("3768");
    BigInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2871;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    BigInteger m("595");
    BigInteger n("376988");
    BigInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 3419;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing second_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    BigInteger m("595");
    BigInteger n("376");
    BigInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing both_numbers_less_than_modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    BigInteger m("59509095449");
    BigInteger n("37654969960");
    BigInteger q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2861;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing both_numbers_greater_than_modulus";
  }

  /************************************************/
  /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
  /************************************************/

  // The method "Mod Sub" operates on BigIntegers m,n,q
  //   Returns:
  //    (m-n)mod q
  //    = {(m mod q) - (n mod q)}mod q	when m>n
  //    = 0 when m=n
  //    = {(m mod q)+q-(n mod q)}mod q when m<n

  //   ConvertToInt converts BigInteger calculatedResult to integer

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    BigInteger m("595");
    BigInteger n("399");
    BigInteger q("406");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 196;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing first_number_greater_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    BigInteger m("39960");
    BigInteger n("595090959");
    BigInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToInt())
      << "Failure testing first_number_less_than_modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    BigInteger m("595090959");
    BigInteger n("595090959");
    BigInteger q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing first_number_equals_second_number";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Mul" operates on BigIntegers m,n,q
  //   Returns:  (m*n)mod q
  //              = {(m mod q)*(n mod q)}mod q
  // ConvertToInt converts BigInteger calculatedResult to integer

  // FIRST > MOD
  {
    BigInteger m("38");
    BigInteger n("4");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 24;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul first > mod";
  }

  // FIRST == MOD
  {
    BigInteger m("32");
    BigInteger n("4");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul first == mod";
  }

  // SECOND > MOD
  {
    BigInteger m("3");
    BigInteger n("37");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 15;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul second > mod";
  }

  // SECOND == MOD
  {
    BigInteger m("3");
    BigInteger n("32");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul second == mod";
  }

  // BOTH > MOD
  {
    BigInteger m("36");
    BigInteger n("37");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 20;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul both > mod";
  }

  // BOTH == MOD
  {
    BigInteger m("32");
    BigInteger n("32");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul both == mod";
  }

  // PRODUCT > MOD
  {
    BigInteger m("39");
    BigInteger n("37");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 3;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul product > mod";
  }

  // PRODUCT == MOD
  {
    BigInteger m("8");
    BigInteger n("4");
    BigInteger q("32");

    BigInteger calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing ModMul product == mod";
  }


  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Exp" operates on BigIntegers m,n,q
  // Returns:  (m^n)mod q
  //   = {(m mod q)^(n mod q)}mod q
  // ConvertToInt converts BigInteger calculatedResult to integer

  {
    BigInteger m("39960");
    BigInteger n("9");
    BigInteger q("406756");

    BigInteger calculatedResult = m.ModExp(n,q);
    uint64_t expectedResult = 96776;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing mod_exp_test";
  }
}

TEST(UTBinInt,big_modexp){
  //very big modexp. 
  {
    bool dbg_flag = false;
    TimeVar t;

    TIC(t);
    BigInteger m("150802716267100577727763462252");
    BigInteger n("507060240091291760598681282151");
    BigInteger q("1014120480182583521197362564303");

    BigInteger calculatedResult = m.ModExp(n,q);
    BigInteger expectedResult("187237443793760596004690725849");

    EXPECT_EQ(expectedResult, calculatedResult)
      << "Failure testing very big mod_exp_test";

    
    DEBUG("big_modexp time ns "<<TOC_NS(t));
  }
}

TEST(UTBinInt,power_2_modexp) {
  {
    BigInteger m("2");
    BigInteger n("50");
    BigInteger q("16");

    BigInteger calculatedResult = m.ModExp(n,q);
    BigInteger expectedResult("0");

    EXPECT_EQ( expectedResult, calculatedResult ) << "Failure testing TWO.ModExp(50,16)";
      
  }
}

TEST(UTBinInt,shift){

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
  //ConvertToInt converts BigInteger calculatedResult to integer

  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39960");
    usshort shift = 3;

    BigInteger calculatedResult = a<<(shift);
    uint64_t expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39960");
    usshort shift = 6;

    BigInteger calculatedResult = a<<(shift);
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
  // ConvertToInt converts BigInteger a to integer




  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39960");
    usshort num = 3;

    a<<=(num);
    uint64_t expectedResult = 319680;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39960");
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
  // ConvertToInt converts BigInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39965675");
    usshort shift = 3;

    BigInteger calculatedResult = a>>(shift);
    uint64_t expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39965675");
    usshort shift = 6;

    BigInteger calculatedResult = a>>(shift);
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
  //   ConvertToInt converts BigInteger calculatedResult to integer


  // TEST CASE WHEN SHIFT IS LESS THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39965675");
    usshort shift = 3;

    a>>=(shift);
    uint64_t expectedResult = 4995709;

    EXPECT_EQ(expectedResult, a.ConvertToInt())
      << "Failure testing shift_less_than_max_shift";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN 4 (MAX SHIFT DONE AT A TIME)
  {
    BigInteger a("39965675");
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

TEST(UTBinInt,method_binary_string_to_big_binary_integer){
  //TEST CASE FOR STATIC METHOD BitStringToBigInteger in BigInteger

 std::string binaryString = "1011101101110001111010111011000000011";
  BigInteger b =
    lbcrypto::BigInteger::BitStringToBigInteger(binaryString);

  BigInteger expectedResult("100633769475");
  EXPECT_EQ(expectedResult, b)
    << "Failure testing BitStringToBigInteger";
}

/****************************************/
/* TESTING METHOD  EXP                  */
/****************************************/
TEST(UTBinInt,method_exponentiation_without_modulus){

  BigInteger x("56");
  BigInteger result = x.Exp(10);

  BigInteger expectedResult("303305489096114176");
  EXPECT_EQ(expectedResult, result)
    << "Failure testing exp";
}

TEST(UTBinInt,method_ConvertToDouble) {
  BigInteger x("104037585658683683");
  double xInDouble = 104037585658683683;

  EXPECT_EQ(xInDouble, x.ConvertToDouble());
}

TEST(UTBinInt,method_getDigitAtIndex) {
	BigInteger x(0xa);

	EXPECT_EQ(x.GetDigitAtIndexForBase(1,2), 0ULL);
	EXPECT_EQ(x.GetDigitAtIndexForBase(2,2), 1ULL);
	EXPECT_EQ(x.GetDigitAtIndexForBase(3,2), 0ULL);
	EXPECT_EQ(x.GetDigitAtIndexForBase(4,2), 1ULL);
}

TEST(UTBinInt, method_GetBitAtIndex){
  bool dbg_flag = false;
  BigInteger x(1);

  x <<=(100); //x has one bit at 100

  x += BigInteger(2); //x has one bit at 2

  DEBUG("x "<<x);
  DEBUG(x.GetInternalRepresentation());
  DEBUG(std::hex <<x.GetInternalRepresentation()<<std::dec); 

  // index is 1 for lsb!
  EXPECT_EQ(x.GetBitAtIndex(1), 0);
  EXPECT_EQ(x.GetBitAtIndex(2), 1);

  for (auto idx = 3; idx < 100; idx++){
    EXPECT_EQ(x.GetBitAtIndex(idx), 0);
  }
  EXPECT_EQ(x.GetBitAtIndex(101), 1);

}


TEST(UTBinInt, method_GetInternalRepresentation){
  bool dbg_flag = false;
  BigInteger x(1);

  x <<=(100); //x has one bit at 128
  x += BigInteger(2); //x has one bit at 2

  auto x_limbs = x.GetInternalRepresentation();

  if (dbg_flag) {
    DEBUG(std::hex <<x.GetInternalRepresentation()<<std::dec); 
    DEBUG(x_limbs);
    DEBUG("x_limbs "<< x_limbs);
    DEBUG("x "<<x);
  }

  //define what is correct based on math backend selected
#if MATHBACKEND == 2
  vector<uint32_t> correct={2,0,0,16};
#elif MATHBACKEND == 4 && defined(UBINT_32)
  vector<uint32_t> correct={2,0,0,16};
#elif MATHBACKEND == 4 && defined(UBINT_64)
  //this configuration is not supported yet
#elif MATHBACKEND == 6
  vector<NTL::ZZ_limb_t> correct={2,68719476736};
#endif
  EXPECT_EQ(correct, x_limbs);
}
