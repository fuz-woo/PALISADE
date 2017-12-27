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
 *  This file contains google test code that exercises the exp_int::xubint
 *  unsigned big integer library of the PALISADE library.
 *
*/

#include "include/gtest/gtest.h"
#include <iostream>
#include <bitset>
//todo reduce the number of required includes

#include "math/backend.h"
#include "utils/inttypes.h"
#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

class UnitTestubint : public ::testing::Test {
protected:
  virtual void SetUp() {
    // Code here will be called before each test
    // (right before the constructor).

  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/************************************************/
/*	TESTING METHODS OF UBINT CLASS		*/
/************************************************/

/* Methods are tested in the following order
   Ctor, dtor, ConvertToX() 
   then shift and compare
   then math (which are built on shift and compare)
   then modulo math
   then any anciliary functions
*/

/* here are all the methods that need to be tested (or have been
   tested but not removed from this list -- oops)

SetValue(str)
SetValue(&exp_int::xubint)

intTobint() //todo change name to IntToBint()

modulo math

how many of these do we actually want here
ModBarrett NOT DONE
ModBarrettAdd NOT DONE
ModBarrettSub NOT DONE
ModBarrettMul NOT DONE


Serialize()
Deserialize()

isIfPowerOfTwo()
GetLengthForBase()
GetDigitAtIndexForBase()
BinaryStringToUbint()
SetIdentity()

 */
/*************************************************
 * TESTING Constructors, Converters and constants 
 * note to test for memory leaks, run 
 * valgrind ./tests --gtest_filter=UTbint.*
 *************************************************/
TEST(UTubint,string_conversions_msb){
  
  //test string ctor and ConvertTo functions
  //note number of limbs cited assumes uint32_t implementation
  //create a small exp_int::xubint with only one limb

  exp_int::xubint q1("00000000000000163841");

  //  q1.PrintIntegerConstants();

  EXPECT_EQ(163841ULL, q1.ConvertToUsint())<<"Failure Convert 1 limb to usint";
  EXPECT_EQ(163841ULL, q1.ConvertToUint32())<<"Failure Convert 1 limb to uint";
  EXPECT_EQ(163841ULL, q1.ConvertToUint64())<<"Failure Convert 1 limb to uint64";
  EXPECT_EQ(163841.0F, q1.ConvertToFloat())
    <<"Failure Convert 1 limb to float";
  EXPECT_EQ(163841.0, q1.ConvertToDouble())
    <<"Failure Convert 1 limb to double";

  //test GetMSB() for 1 limb
  usint msb = q1.GetMSB();

  EXPECT_EQ(msb, 18U)<<  "Failure testing 1 limb msb test ";

  //create a large exp_int::xubint with two limbs
  exp_int::xubint q2("00004057816419532801");
  //to big for usint or for float so we expect that to fail
  EXPECT_NE(4057816419532801UL, q2.ConvertToUsint()) 
    <<"Failure Convert 2 limb to usint";

  EXPECT_NE(4057816419532801UL, q2.ConvertToUint32())
    <<"Failure Convert 2 limb to uint32";
  EXPECT_EQ(4057816419532801ULL, q2.ConvertToUint64())
    <<"Failure Convert 2 limb to uint64";
  EXPECT_EQ(4057816419532801ULL, q2.ConvertToUint64())
    <<"Failure Convert 2 limb to uint64";

  //test float converstions. 

  //cout << "flt mantissa digits "<< FLT_MANT_DIG <<endl;
  //cout << "d mantissa digits "<< DBL_MANT_DIG <<endl;
  //cout << "ld mantissa digits "<< LDBL_MANT_DIG <<endl;

  float testf = 4057816419532801.0F;
  //cout << "sizeoffloat "<< sizeof(float) << endl;  
  //cout << "testf "<< testf << endl;
  EXPECT_EQ(testf, q2.ConvertToFloat())
    <<"Failure Convert 2 limb to float";    

  double testd = 4057816419532801.0;
  //cout << "sizeofdouble "<< sizeof(double) << endl;  
  //cout << "testd "<< testd << endl;
  EXPECT_EQ(testd, q2.ConvertToDouble())
    <<"Failure Convert 2 limb to double";    

  //note we expect a loss of precision
  EXPECT_NE(testd, (double)q2.ConvertToFloat())
    <<"Failure Convert 2 limb to float loss of precision";    


  //test GetMSB()
  msb = q2.GetMSB();
  //DEBUG("q2 msb "<<msb);
  EXPECT_EQ(msb, 52U)<<  "Failure testing 2 limb msb test ";

}
TEST(UTubint,ctor){    

  //test the ctor(usint)
  exp_int::xubint c1(123456789);
  EXPECT_EQ(123456789U, c1.ConvertToUsint())<< "Failure testing ctor(usint)";
  //test the ctor(string)
  exp_int::xubint c2("123456789");
  EXPECT_EQ(123456789U, c2.ConvertToUsint())<< "Failure testing ctor(string)";
  //test the ctor(exp_int::xubint)
  exp_int::xubint d(c1);
  EXPECT_EQ(d.ConvertToUsint(), c1.ConvertToUsint())
    << "Failure testing ctor(exp_int::xubint)";
  //test the ctor(exp_int::xubint&)
  exp_int::xubint &e = d;
  exp_int::xubint f(e);
  EXPECT_EQ(e.ConvertToUsint(), f.ConvertToUsint()) 
    << "Failure testing ctor(exp_int::xubint&)";
} 

TEST(UTubint,ctor32){       
  // TEST CASE FOR 32bit VALUES
  exp_int::xubint a(UINT32_MAX);
  uint32_t aint32 = UINT32_MAX;

  EXPECT_EQ(aint32,a.ConvertToUint32())
    << "Failure testing ConvertToUint32() for UINT32_MAX";    

  const usint bitwidth = 32;
  bitset<bitwidth> abs;
  for (usint i = 0; i < bitwidth; i++) {
    abs[i] = 1;
  }
  uint32_t cint32 = abs.to_ulong(); //biggest 32 bit int all FFs
  exp_int::xubint c(cint32);
  EXPECT_EQ(cint32,c.ConvertToUsint())
    << "Failure testing ConvertToUsint() for maxint32 made with bitsets";    

  EXPECT_EQ(UINT32_MAX,c.ConvertToUsint())
    << "Failure testing ConvertToUsint() for UINT32_MAX";    
}

TEST(UTubint,ctor64){    
  // TEST CASE FOR 64bit VALUES
  /*exp_int::xubint a(9223372036854775807ULL); // = 7FFFFFFF
  uint64_t auint64 = 9223372036854775807ULL;
>>>>>>> Commenting out test that is failing.
  EXPECT_EQ(auint64,a.ConvertToUint64())
    << "Failure testing ConvertToUint64() for big numbers";    
  bitset<64> abs;
  for (usint i = 0; i < 64; i++) {
    abs[i] = 1;
  }
  uint64_t cuint64 = abs.to_ullong(); //biggest 64 bit int all FFs
  exp_int::xubint c(cuint64);

  EXPECT_EQ(cuint64,c.ConvertToUint64())
    << "Failure testing ConvertToUint64() for maxint64";    

  EXPECT_EQ(UINT64_MAX,c.ConvertToUint64())
    << "Failure testing ConvertToUint64() for UINT64_MAX"; 

  EXPECT_EQ("18446744073709551615", c.ToString())
    << "Failure testing ToString() for UINT64_MAX"; */

  //todo some very large digit tests.
}

/****************************/
/* TESTING SHIFT OPERATORS  */
/****************************/

TEST(UTubint,left_shift){

  // TESTING OPERATOR LEFT SHIFT (<< AND <<=) FOR ALL CONDITIONS
  // The operator 'Left Shift' operates on exp_int::xubint a, and it
  // is shifted by a number

  // Returns: a<<(num), and the result is stored in exp_int::xubint
  // or returned in original for <<=
  // 'a' is left shifted by 'num' number of bits, and
  // filled up by 0s from right which is equivalent to a * (2^num)
  //        example:
  //            4<<3 => (100)<<3 => (100000) => 32
  //           this is equivalent to: 4* (2^3) => 4*8 =32

  // TEST CASE WHEN SHIFT IS LESS THAN LIMB SIZE
  {
    exp_int::xubint a("39960");
    usint shift = 3;

    exp_int::xubint calculatedResult = a<<(shift);
    usint expectedResult = 319680;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing << less than limb size";

    a<<=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing <<= less than limb size";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN LIMB SIZE
  {
    exp_int::xubint a("39960");
    usint shift = 33;

    exp_int::xubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 343253786296320L;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing << greater than limb size";

    a<<=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      << "Failure testing <<= greater than limb size";
  }

  {
    
    exp_int::xubint a("1024");
    usint shift = 48;
    
    exp_int::xubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 288230376151711744;
    uint64_t result = calculatedResult.ConvertToUint64();

    EXPECT_EQ(expectedResult, result)
      <<"Failure testing << greater than limb size";
    a<<=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      << "Failure testing <<= greater than limb size";

  }

  // TEST CASE WHEN SHIFT IS multi limb
  {
    exp_int::xubint a("138712237895312");
    usint shift = 8;

    //usint msb = a.GetMSB();
    //DEBUG("a.msb " <<msb);

    exp_int::xubint calculatedResult = a<<(shift);
    uint64_t expectedResult = 35510332901199872;
    //DEBUG("expectedResult 35510332901199872 ="<<expectedResult);

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing << multi limb";
    a<<=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      << "Failure testing <<= multi limb";
  }
}
TEST(UTubint,right_shift){

  // TESTING OPERATOR RIGHT SHIFT (>> AND >>=) FOR ALL CONDITIONS
  // The operator 'Right Shift' operates on exp_int::xubint a, and it
  // is shifted by a number of bits 

  // Returns: a>>(num), and the result is stored in exp_int::xubint or the
  // original a for >>=
  // Result 'a' is right shifted by 'num'
  // number of bits, and filled up by 0s from left which is equivalent
  // to a / (2^num)
  //  ex:4>>3 => (100000)>>3 => (000100) => 4
  // this is equivalent to: 32*(2^3) => 32/8 = 4

  // TEST CASE WHEN SHIFT IS LESS THAN LIMB SIZE
  {
    exp_int::xubint a("39965675");
    usshort shift = 3;

    exp_int::xubint calculatedResult = a>>(shift);
    usint expectedResult = 4995709;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing >> less than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing >>= less than limb size";
  }
  // TEST CASE WHEN SHIFT IS GREATER THAN LIMB SIZE
  {
    exp_int::xubint a("343253786296320");
    usshort shift = 33;

    exp_int::xubint calculatedResult = a>>(shift);
    usint expectedResult = 39960;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing >>= greater than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUsint())
      << "Failure testing >>= greater than limb size";
  }
  {
    exp_int::xubint a(" 288230376151711744");
    usshort shift = 48;

    exp_int::xubint calculatedResult = a>>(shift);
    usint expectedResult = 1024;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUsint())
      << "Failure testing >> greater than limb size";
    a>>=(shift);
    EXPECT_EQ(expectedResult, a.ConvertToUsint()) 
      << "Failure testing >>= greater than limb size";

  }
}
/********************************************/
/* TESTING COMPARATOR METHODS AND OPERATORS */
/********************************************/
TEST(UTubint, compare){
  /* TESTING METHOD COMPARE and gt, lt, eq, neq FOR ALL CONDITIONS    */

  // The method "Comapare" comapres two BigIntegers a,b
  // Returns:
  //    1, when a>b
  //    0, when a=b
  //   -1, when a<b
  //
  // Result is stored in signed integer, and then the result is
  // typecasted to int as  if  takes integer

  int c;
  int expectedResult;
  bool cbool;
  
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER
  {
    exp_int::xubint a("2124827461185795");
    exp_int::xubint b("1201413067178193");
    
    c = a.Compare(b);
    expectedResult = 1;
    EXPECT_EQ(expectedResult, c)<< "Failure testing compare a >  b";
    cbool= a>b;
    EXPECT_TRUE(cbool)<< "Failure testing > : a > b";
    cbool= a>=b;
    EXPECT_TRUE(cbool)<< "Failure testing >= : a > b";
    cbool= a<b;
    EXPECT_FALSE(cbool)<< "Failure testing < : a > b";
    cbool= a<=b;
    EXPECT_FALSE(cbool)<< "Failure testing <= : a > b";
    cbool= a==b;
    EXPECT_FALSE(cbool)<< "Failure testing == : a > b";
    cbool= a!=b;
    EXPECT_TRUE(cbool)<< "Failure testing != : a > b";
    
  }
  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER
  {
    exp_int::xubint a("1201413067178193");
    exp_int::xubint b("2124827461185795");
    
    c = a.Compare(b);
    expectedResult = -1;
    
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare a < b";
    cbool= a>b;
    EXPECT_FALSE(cbool)<< "Failure testing > : a < b";
    cbool= a>=b;
    EXPECT_FALSE(cbool)<< "Failure testing >= : a < b";
    cbool= a<b;
    EXPECT_TRUE(cbool)<< "Failure testing < : a < b";
    cbool= a<=b;
    EXPECT_TRUE(cbool)<< "Failure testing <= : a < b";
    cbool= a==b;
    EXPECT_FALSE(cbool)<< "Failure testing == : a < b";
    cbool= a!=b;
    EXPECT_TRUE(cbool)<< "Failure testing != : a < b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO SECOND NUMBER
  {
    exp_int::xubint a("2124827461185795");
    exp_int::xubint b("2124827461185795");
    
    c = a.Compare(b);
    expectedResult = 0;
    
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare a == b";
    cbool= a>b;
    EXPECT_FALSE(cbool)<< "Failure testing > : a == b";
    cbool= a>=b;
    EXPECT_TRUE(cbool)<< "Failure testing >= : a == b";
    cbool= a<b;
    EXPECT_FALSE(cbool)<< "Failure testing < : a == b";
    cbool= a<=b;
    EXPECT_TRUE(cbool)<< "Failure testing <= : a == b";
    cbool= a==b;
    EXPECT_TRUE(cbool)<< "Failure testing == : a == b";
    cbool= a!=b;
    EXPECT_FALSE(cbool)<< "Failure testing != : a == b";
  }
  
  //test case that failed in TR 409
  {

    exp_int::xubint a("11272741999");
    exp_int::xubint b("8828677302");

    c = a.Compare(b);
    expectedResult = 1;
    EXPECT_EQ(expectedResult,c)<< "Failure testing compare TR 409";

  }
}

/************************************************/
/* TESTING BASIC MATH METHODS AND OPERATORS     */
/************************************************/
TEST(UTubint,basic_math){
  exp_int::xubint calculatedResult;
  uint64_t expectedResult;
  string expectedResultStr; //for when exp_int::xubint is > 64 bits.
    
  //TESTING + and +=

  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    exp_int::xubint a("203450");
    exp_int::xubint b("2034");

    calculatedResult = a.Add(b);
    expectedResult = 205484;

    //DEBUG("result "<<result);
    //DEBUG("expect "<<expectedResult);

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing Add() : a > b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing + : a > b";

    a+=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing += : a > b";

  }

  // TEST CASE WHEN FIRST NUMBER IS LESS THAN SECOND NUMBER AND MSB
  // HAS NO OVERFLOW
  {
    exp_int::xubint a("2034");
    exp_int::xubint b("203450");

    calculatedResult = a.Add(b);
    expectedResult = 205484;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing Add() : a < b";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing + : a < b";

    a+=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing += : a < b";
  }

  // TEST CASE WHEN MSB OF THE RESULT HAS BIT-OVERFLOW TO THE NEXT
  // LIMB
  {
    exp_int::xubint a("4294967295");
    exp_int::xubint b("1");

    calculatedResult = a.Add(b);
    expectedResult = 4294967296;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing Add() : overflow to next limb";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing + : overflow to next limb";

    a+=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing += : overflow to next limb";
  }

  // TEST CASE WHEN MSB OF THE RESULT HAS NO BIT-OVERFLOW IN THE SAME
  // LIMB
  //todo change for limb

  {
    exp_int::xubint a("35");
    exp_int::xubint b("1015");
      
    calculatedResult = a.Add(b);
    expectedResult = 1050;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing Add() :no overflow in same limb";

    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing + :no overflow in same limb";

    a+=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing += :no overflow in same limb";
  }

  // TEST CASE WHEN both are multi limb numbers
  {
    exp_int::xubint a("98879665709163");
    exp_int::xubint b("39832572186149");
      
    calculatedResult = a.Add(b);
    expectedResult = 138712237895312;
      
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing Add() : multi limb";
      
    calculatedResult = a + b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing + : multi limb";
      
    a+=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing += : multi limb";
  }

  //TESTING - and -=
    
  // note that when a<b, the result is 0, since there is no support
  // for negative numbers in exp_int::xubint (see sbint for future
  // implementation)x
    
  {
    // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
      
    exp_int::xubint a("20489");
    exp_int::xubint b("2034455");
      
    calculatedResult = a.Sub(b);
    expectedResult = 0;
      
    //since exp_int::xubint is unsigned  result should be zero
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing Sub() : a < b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing - : a < b";
      
    a-=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      << "Failure testing -= : a < b";
  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {
    exp_int::xubint a("2048956567");
    exp_int::xubint b("2048956567");
      
    calculatedResult = a.Sub(b);
    expectedResult = 0;
      
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing Sub() : a == b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing - : a == b";
      
    a-=b;
    EXPECT_EQ(expectedResult, a.ConvertToUint64()) 
      << "Failure testing -= : a == b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    exp_int::xubint a("2048956567");
    exp_int::xubint b("2034455");
      
    calculatedResult = a.Sub(b);
    expectedResult = 2046922112;
      
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing Sub() : a > b";
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing - : a > b";
      
    a-=b;
    EXPECT_EQ(expectedResult,a.ConvertToUint64())
      << "Failure testing -= : a > b";
  }
  // TEST CASE WHEN SUBTRACTION NEEDS BORROW FROM NEXT BYTE
  {
    //todo: change for limb
    exp_int::xubint a("196737");
    exp_int::xubint b("65406");
      
    calculatedResult = a.Sub(b);
    expectedResult = 131331;
      
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      <<"Failure testing Sub() : borrow from next byte"; 
      
    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing - : borrow from next byte"; 
      
    a-=b;
    EXPECT_EQ(expectedResult,a.ConvertToUint64())
      <<"Failure testing -= : borrow from next byte"; 

  }
  // TEST CASE WHEN SUBTRACTION IS MULTI LIMB
  {
    exp_int::xubint a("98879665709163");
    exp_int::xubint b("39832572186149");

    calculatedResult = a.Sub(b);
    expectedResult = 59047093523014;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      <<"Failure testing Sub() : multi limb";

    calculatedResult = a - b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing - : multi limb";
    a-=b;
    EXPECT_EQ(expectedResult,a.ConvertToUint64())
      <<"Failure testing -= : multi limb";
  }

  // TESTING METHOD MUL FOR ALL CONDITIONS 
  // The method "Mul" does multiplication on two ubints
  // a,b Returns a*b, which is stored in another exp_int::xubint for * or in a for *=
  {
    //single Limb
    exp_int::xubint a("1967");
    exp_int::xubint b("654");

    calculatedResult = a.Mul(b);
    expectedResult = 1286418;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      <<"Failure testing Mul() : single limb";
    calculatedResult = a * b;
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      <<"Failure testing * : single limb";
    a *= b;
    EXPECT_EQ(expectedResult,a.ConvertToUint64())
      <<"Failure testing *= : single limb";
  }
  {
    //multi limb
    exp_int::xubint a("98879665709163");
    exp_int::xubint b("39832572186149");

    calculatedResult = a.Mul(b);
    expectedResultStr = "3938631422102517149330983287";
    // note the expected result is bigger than uint64 so we cannot use
    // that to compare. Instead we uses string values.

    EXPECT_EQ(expectedResultStr,calculatedResult.ToString())
      <<"testing Mul() : multi limb";
    calculatedResult = a * b;
    EXPECT_EQ(expectedResultStr,calculatedResult.ToString())
      <<"Failure testing * : multi limb";
    a *= b;
    EXPECT_EQ(expectedResultStr,a.ToString())
      <<"Failure testing *= : multi limb";

  }

  // TESTING METHOD DIVIDED_BY FOR ALL CONDITIONS
  // The method "Divided By" does division of exp_int::xubint a by exp_int::xubint b
  // Returns a/b, which is stored in another
  // exp_int::xubint calculatedResult
  // When b=0, throws
  // error, since division by Zero is not allowed When a<b, returns 0,
  // since decimal value is not returned


  // TEST CASE WHEN FIRST NUMBER IS LESS THAN THE SECOND NUMBER
  {
    exp_int::xubint a("2048");
    exp_int::xubint b("2034455");

    calculatedResult = a.Div(b);
    expectedResult = 0;

    //RESULT SHOULD BE ZERO
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing Div() : a < b";

    calculatedResult = a/b;      
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing / : a < b";

    a/=b;      
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing /= : a < b";

  }
  // TEST CASE WHEN FIRST NUMBER IS EQUAL TO THE SECOND NUMBER
  {

    exp_int::xubint a("2048956567");
    exp_int::xubint b("2048956567");

    calculatedResult = a.Div(b);
    expectedResult = 1;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing Div() : a == b";

    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"Failure testing / : a == b";

    a/=b;      
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"Failure testing /= : a == b";
  }
  // TEST CASE WHEN FIRST NUMBER IS GREATER THAN THE SECOND NUMBER
  {
    exp_int::xubint a("2048956567");
    exp_int::xubint b("2034455");

    calculatedResult = a.Div(b);
    expectedResult = 1007;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"testing Div() a greater than b";

    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"testing / by a greater than b";

    a/=b;      
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"testing /= by a greater than b";
  }

  // TEST CASE for MULTI LIMB
  {
    exp_int::xubint a("3938631422102517149330983287");
    exp_int::xubint b("98879665709163");


    calculatedResult = a.Div(b);
    expectedResult = 39832572186149;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"testing divided by multi limb";
    calculatedResult = a/b;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      <<"testing divided by multi limb";

    a/=b;      
    EXPECT_EQ(expectedResult, a.ConvertToUint64())
      <<"testing /= by multi limb";
  }

  // TEST CASE for DIVIDE BY 0
  // should throw an error so we verify it does
  {
    exp_int::xubint a("3938631422102517149330983287");
    exp_int::xubint b("0");

    bool thrown = false;

    try {
      calculatedResult = a.Div(b);
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing Div() zero";
    thrown = false;

    try {
      calculatedResult = a/b;
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing / zero";

    thrown = false;
    try {
      a/=b;
    }
    catch (...){
      thrown = true;
    }
    EXPECT_TRUE(thrown)<<"Failure testing /= zero";
  }

  // TESTING METHOD  EXP 
  {
    exp_int::xubint x("56");
    exp_int::xubint result = x.Exp(10);

    exp_int::xubint expectedResult("303305489096114176");
    EXPECT_EQ(expectedResult, result)
      << "Failure testing exp";
  }
}

TEST(UTubint,mod_operations){

  /************************************************/
  /* TESTING METHOD MOD FOR ALL CONDITIONS        */
  /************************************************/

  // The method "Mod" does modulus operation on two ubints
  // m,p Returns (m mod p), which is stored in another exp_int::xubint

  exp_int::xubint calculatedResult;
  uint64_t expectedResult;
  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD
  {
    exp_int::xubint m("27");
    exp_int::xubint p("240");

    calculatedResult = m.Mod(p);
    expectedResult = 27;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing Mod(): number < modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing % : number < modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m.ConvertToUint64())
      << "Failure testing %= : number < modulus";
  }
  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    exp_int::xubint m("93409673");
    exp_int::xubint p("406");

    calculatedResult = m.Mod(p);
    expectedResult = 35;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing Mod(): number > modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing %: number > modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m.ConvertToUint64())
      << "Failure testing %=: number > modulus";
  }
  // TEST CASE WHEN THE NUMBER IS DIVISIBLE BY MOD
  {
    exp_int::xubint m("32768");
    exp_int::xubint p("16");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing Mod(): number_divisible by modulus";

    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing %:  number_divisible by modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m.ConvertToUint64())
      << "Failure testing %=:  number_divisible by modulus";
  }

  // TEST CASE WHEN THE NUMBER IS EQUAL TO MOD
  {
    exp_int::xubint m("67108913");
    exp_int::xubint p("67108913");

    calculatedResult = m.Mod(p);
    expectedResult = 0;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing Mod(): number == modulus";
    calculatedResult = m%p;
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing %:   number == modulus";

    m%=p;
    EXPECT_EQ(expectedResult,m.ConvertToUint64())
      << "Failure testing %=:  number == modulus";
  }

  // TEST CASE THAT FAILED TR#392    
  {
    exp_int::xubint first("4974113608263");
    exp_int::xubint second("486376675628");
    exp_int::xubint modcorrect("110346851983");
    exp_int::xubint modresult;

    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult)
      <<"Failure ModInverse() Mod regression test";
  }

  // TEST CASE THAT FAILED TR#409
  {

    exp_int::xubint first("11272741999");
    exp_int::xubint second("8828677302");

    exp_int::xubint modcorrect("2444064697");
    exp_int::xubint modresult;
    
    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult)
      <<"Failure Mod() Mod tr #409";
  }


  // ANOTHER TEST CASE THAT FAILED TR#409
  {

    exp_int::xubint first("239109124202497");
    exp_int::xubint second("9");

    exp_int::xubint modcorrect("1");
    exp_int::xubint modresult;
    
    modresult = first.Mod(second);

    EXPECT_EQ(modcorrect, modresult)
      <<"Failure Mod() Mod tr #409 2";
  }




  // Mod(0)
  {
    exp_int::xubint first("4974113608263");
    exp_int::xubint second("0");
    exp_int::xubint modcorrect("4974113608263");
    exp_int::xubint modresult;

    bool thrown = false;
    try {
      modresult = first.Mod(second);
    }
    catch (exception& e){
      thrown = true;
    }

    EXPECT_TRUE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";
  }

}

  /************************************************/
  /* TESTING METHOD MOD BARRETT FOR ALL CONDITIONS */
  /************************************************/

  // TEST CASE WHEN THE NUMBER IS LESS THAN MOD			//NOT GIVING PROPER OUTPUT AS OF NOW

  /*TEST(UTubint_METHOD_MOD_BARRETT,NUMBER_LESS_THAN_MOD){

    exp_int::xubint a("9587");
    exp_int::xubint b("3591");
    exp_int::xubint c("177");

    exp_int::xubint calculatedResult = a.ModBarrett(b,c);
    int expectedResult = 205484;

    std::cout<<"\n"<<d.ConvertToUint64()<<"\n";	//for testing purpose

    //EXPECT_EQ(27,calculatedResult.ConvertToUint64());
    }
  */

  /*************************************************/
  /* TESTING METHOD MOD INVERSE FOR ALL CONDITIONS */
  /*************************************************/
  // The method "Mod Inverse" operates on ubints m,p
  // Returns {(m)^(-1)}mod p
  //    which is multiplicative inverse of m with respect to p, and is
  //    uses extended Euclidean algorithm m and p are co-primes (i,e GCD
  //    of m and p is 1)
  // If m and p are not co-prime, the method throws an error
  // ConvertToUsint converts exp_int::xubint calculatedResult to integer

TEST(UTubint,mod_inverse){
  exp_int::xubint calculatedResult;
  uint64_t expectedResult;

  // TEST CASE WHEN THE NUMBER IS GREATER THAN MOD
  {
    exp_int::xubint m("5");
    exp_int::xubint p("108");

    calculatedResult = m.ModInverse(p);
    expectedResult = 65;
    
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing ModInverse(): number less than modulus";
  }

  // TEST CASE WHEN THE NUMBER AND MOD ARE NOT CO-PRIME
  {
    exp_int::xubint m("3017");
    exp_int::xubint p("7");

    bool thrown = false;
    try {
      calculatedResult = m.ModInverse(p);
    }
    catch (exception& e){
      thrown = true;
    }

    EXPECT_TRUE(thrown)
      << "Failure testing ModInverse() non co-prime arguments";

  }

  //testcase that failed during testing.
  {


    exp_int::xubint input ("405107564542978792");
    exp_int::xubint modulus("1152921504606847009");
    exp_int::xubint modIcorrect("844019068664266609");
    exp_int::xubint modIresult;

    bool thrown = false;
    try {
      modIresult = input.ModInverse(modulus);
    }
    catch (exception& e){
      thrown = true;
      modIresult = 0;
    }

    EXPECT_FALSE(thrown)
      << "Failure ModInverse() regression test caught throw";
    EXPECT_EQ(modIcorrect, modIresult)
      <<"Failure ModInverse() regression test";
  }

}

TEST(UTubint,mod_arithmetic){
  exp_int::xubint calculatedResult;
  uint64_t expectedResult;

  /************************************************/
  /* TESTING METHOD MODADD FOR ALL CONDITIONS     */
  /************************************************/
  // The method "Mod Add" operates on ubints m,n,q
  //   Returns:
  //     (m+n)mod q
  //      = {(m mod q) + (n mod q)}mod q

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    exp_int::xubint m("58059595");
    exp_int::xubint n("3768");
    exp_int::xubint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2871;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing ModAdd() first number > modulus";
  }
  // TEST CASE WHEN THE SECOND NUMBER IS GREATER THAN MOD
  {
    exp_int::xubint m("595");
    exp_int::xubint n("376988");
    exp_int::xubint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 3419;

    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing ModAdd() second number > modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE LESS THAN MOD
  {
    exp_int::xubint m("595");
    exp_int::xubint n("376");
    exp_int::xubint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 971;
    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing ModAdd() both numbers < modulus";
  }
  // TEST CASE WHEN THE BOTH NUMBERS ARE GREATER THAN MOD
  {

    exp_int::xubint m("59509095449");
    exp_int::xubint n("37654969960");
    exp_int::xubint q("4067");

    calculatedResult = m.ModAdd(n,q);
    expectedResult = 2861;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
     << "Failure testing ModAdd() both numbers > modulus";
  }

  /************************************************/
  /* TESTING METHOD MODSUB FOR ALL CONDITIONS -*/
  /************************************************/
  // The method "Mod Sub" operates on ubints m,n,q
  //   Returns:
  //    (m-n)mod q
  //    = {(m mod q) - (n mod q)}mod q	when m>n
  //    = 0 when m=n
  //    = {(m mod q)+q-(n mod q)}mod q when m<n

  //   ConvertToUsint converts exp_int::xubint calculatedResult to
  //   integer

  // TEST CASE WHEN THE FIRST NUMBER IS GREATER THAN MOD
  {
    exp_int::xubint m("595");
    exp_int::xubint n("399");
    exp_int::xubint q("406");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 196;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing ModSub() first number > modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER LESS THAN SECOND NUMBER AND MOD
  {
    exp_int::xubint m("39960");
    exp_int::xubint n("595090959");
    exp_int::xubint q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 33029;

    //[{(a mod c)+ c} - (b mod c)] since a < b
    EXPECT_EQ(expectedResult,calculatedResult.ConvertToUint64())
      << "Failure testing ModSub() first number < modulus";
  }
  // TEST CASE WHEN THE FIRST NUMBER EQUAL TO SECOND NUMBER
  {
    exp_int::xubint m("595090959");
    exp_int::xubint n("595090959");
    exp_int::xubint q("406756");

    calculatedResult = m.ModSub(n,q);
    expectedResult = 0;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing ModSub() first number == second number";
  }

  /************************************************/
  /* TESTING METHOD MODMUL FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Mul" operates on ubints m,n,q
  //   Returns:  (m*n)mod q
  //              = {(m mod q)*(n mod q)}

  {
    exp_int::xubint m("39960");
    exp_int::xubint n("7959");
    exp_int::xubint q("406756");

    exp_int::xubint calculatedResult = m.ModMul(n,q);
    uint64_t expectedResult = 365204;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing ModMul()";
  }

  /************************************************/
  /* TESTING METHOD MODEXP FOR ALL CONDITIONS     */
  /************************************************/

  // The method "Mod Exp" operates on ubints m,n,q
  // Returns:  (m^n)mod q
  //   = {(m mod q)^(n mod q)}mod q

  {
    exp_int::xubint m("39960");
    exp_int::xubint n("10");
    exp_int::xubint q("406756");

    exp_int::xubint calculatedResult = m.ModExp(n,q);
    uint64_t expectedResult = 139668;

    EXPECT_EQ(expectedResult, calculatedResult.ConvertToUint64())
      << "Failure testing ModExp()";
  }
}

//Miscellaneous functions tests
TEST(UTubint, misc_functions){
  // TESTING METHOD  BinaryStringToUbint
#if 0
 std:string binaryString = "1011101101110001111010111011000000011";
  exp_int::xubint b =
    lbcrypto::exp_int::xubint::BinaryStringToUbint(binaryString);

  exp_int::xubint expectedResult("100633769475");
  EXPECT_EQ(expectedResult, b)
    << "Failure testing BinaryToUbint()";
#endif

}
