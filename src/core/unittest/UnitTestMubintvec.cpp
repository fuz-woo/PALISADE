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
 *  This file contains google test code that exercises the big int
 *  vector library of the PALISADE lattice encryption library.
 *
 */

//todo reduce the number of required includes
#include "include/gtest/gtest.h"
#include <iostream>
#include <fstream>

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

using namespace std;
using namespace lbcrypto;

/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/
class UnitTestmubintvec : public ::testing::Test {
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

/* list of tests left to run 
   //todo update this. 

  explicit exp_int::xmubintvec(const usint length, const bint_el_t & modulus);
  explicit exp_int::xmubintvec(const usint length, const std::string& modulus);
  explicit exp_int::xmubintvec(const std::vector<std::string> &s, const bint_el_t &modulus
  explicit exp_int::xmubintvec(const std::vector<std::string> &s, const std::string &modulus);

  void SetModulus(const uint& value);
  void SetModulus(const bint_el_t& value);
  void SetModulus(const std::string& value);
  const bint_el_t& GetModulus() const;

   //METHODS
   //todo write Div and /= vector scalar and vector vector
   
   Exp(const bint_el_t &b)

   GetDigitAtIndexForBase(usint index, usint base) const;
   
   //JSON FACILITY
   Serialize()
   Deserialize()
*/

/************************************************
 *	TESTING BASIC METHODS OF mubintvec CLASS
 ************************************************/
TEST(UTmubintvec,ctor_access_eq_neq){
  bool dbg_flag = false;
  exp_int::xubint q("1234567"); // a bigger number
  
  exp_int::xmubintvec m(5); // calling constructor to create a vector of length 5
  //note all values are zero.
  
  m.SetModulus(q);
  
  exp_int::xmubintvec n(5,q); // calling contructor with modulus
  
  usint i;
  usint j;
  
  EXPECT_EQ(5U,m.GetLength())<< "Failure in GetLength()";
  EXPECT_EQ(5U,n.GetLength())<< "Failure in GetLength()";

  // Old fashioned soon to be deprecated way of 
  // setting value of the value at different index locations

  //test at(string)
  m.at(0)="9868";  
  m.at(1)="5879";
  m.at(2)="4554";
  m.at(3)="2343";
  m.at(4)="4624";
  
  DEBUG("m "<<m);
  EXPECT_EQ(9868U,m.at(0).ConvertToUsint())
    << "Failure in at(0)";
  
  
  //old fashioned way of expect
  EXPECT_EQ(9868U,m.at(0).ConvertToUsint())
    << "Failure in at(str)";
  EXPECT_EQ(5879U,m.at(1).ConvertToUsint())
    << "Failure in at(str)";
  EXPECT_EQ(4554U,m.at(2).ConvertToUsint())
    << "Failure in at(str)";
  EXPECT_EQ(2343U,m.at(3).ConvertToUsint())
    << "Failure in at(str)";
  EXPECT_EQ(4624U,m.at(4).ConvertToUsint())
    << "Failure in at(str)";
  
  EXPECT_EQ(exp_int::xubint(9868U),m.at(0))<< "Failure in at()";
  EXPECT_EQ(exp_int::xubint(5879U),m.at(1))<< "Failure in at()";
  EXPECT_EQ(exp_int::xubint(4554U),m.at(2))<< "Failure in at()";
  EXPECT_EQ(exp_int::xubint(2343U),m.at(3))<< "Failure in at()";
  EXPECT_EQ(exp_int::xubint(4624U),m.at(4))<< "Failure in at()";
  
  //new way of setting value of the value at different index locations
  n[0]="4";
  n[1]=9;   //int (implied)
  n[2]=exp_int::xubint("66"); //exp_int::xubint
  n[3] = 33L;  //long
  n[4] = 7UL;  //unsigned long
  
  // new way of accessing
  EXPECT_EQ(exp_int::xubint(4),n[0])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(9),n[1])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(66),n[2])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(33),n[3])<< "Failure in []";
  EXPECT_EQ(exp_int::xubint(7),n[4])<< "Failure in []";
  
  //test at(exp_int::xubint)
  n.at(0)=exp_int::xubint("4");
  n.at(1)=exp_int::xubint("9");
  n.at(2)=exp_int::xubint("66");
  n.at(3)=exp_int::xubint("33");
  n.at(4)=exp_int::xubint("7");
  

  EXPECT_EQ(exp_int::xubint(4),n[0])<< "Failure in at(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(9),n[1])<< "Failure in at(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(66),n[2])<< "Failure in at(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(33),n[3])<< "Failure in at(exp_int::xubint)";
  EXPECT_EQ(exp_int::xubint(7),n[4])<< "Failure in at(exp_int::xubint)";

  m+=n;

  usint expectedResult[5] = {9872,5888,4620,2376,4631};

  for (i=0,j=0;j<5;i++,j++) {
    EXPECT_EQ (expectedResult[i], (m.at(j)).ConvertToUsint())
      << "Failure testing method_plus_equals";
  }

  //test initializer list of various types
  exp_int::xmubintvec expectedvecstr(5);
  expectedvecstr = {"9872","5888","4620","2376","4631"}; //strings
  expectedvecstr.SetModulus(q);
  EXPECT_EQ (expectedvecstr, m)<< "Failure string initializer list";

  exp_int::xmubintvec expectedvecint(5);
  expectedvecint.SetModulus(q);

  //  expectedvecint = {exp_int::xubint(9872U),exp_int::xubint(5888U),exp_int::xubint(4620U),exp_int::xubint(2376U),exp_int::xubint(4631U)}; //ubints
//  EXPECT_EQ (expectedvecint, m)<< "Failure exp_int::xubint initializer list";

  expectedvecint = {9872ULL,5888ULL,4620ULL,2376ULL,4631ULL}; //usints
  EXPECT_EQ (expectedvecint, m)<< "Failure usint initializer list";

  expectedvecint = {9872,5888,4620,2376,4631}; //ints (compiler promotes)
  EXPECT_EQ (expectedvecint, m)<< "Failure int initializer list";

  //test Single()
  exp_int::xmubintvec s = exp_int::xmubintvec::Single(exp_int::xubint("3"),exp_int::xubint("5"));//value 3, mod 5
  EXPECT_EQ(1U, s.GetLength()) <<"Failure Single.GetLength()";
  EXPECT_EQ(exp_int::xubint(3), s[0]) <<"Failure Single() value";

  // test assignment of single exp_int::xubint (puts it in the 0 the position), zeros
  // out the rest
  //test that the vector is zeroed on init like this.
  exp_int::xmubintvec eqtest(10);
  EXPECT_EQ ( 10U, eqtest.GetLength()) << "Failure create exp_int::xmubintvec of 10 zeros";

  for (i = 0; i< eqtest.GetLength(); i++) {
    EXPECT_EQ ( exp_int::xubint(0U), eqtest[i]) << "Failure create exp_int::xmubintvec of zeros";
  }

  // test assignment of single exp_int::xubint
  eqtest = exp_int::xubint(1);
  EXPECT_EQ (exp_int::xubint(1),  eqtest[0]) << "Failure assign single exp_int::xubint 0 index";
  for (i = 1; i< eqtest.GetLength(); i++) {
    EXPECT_EQ ( exp_int::xubint(0U), eqtest[i]) << "Failure assign single exp_int::xubint nonzero index";
  }

  // test assignment of single usint
  eqtest = 5U;
  EXPECT_EQ (exp_int::xubint(5U),  eqtest[0]) << "Failure assign single exp_int::xubint 0 index";
  for (i = 1; i< eqtest.GetLength(); i++) {
    EXPECT_EQ ( exp_int::xubint(0U), eqtest[i]) << "Failure assign single exp_int::xubint nonzero index";
  }

  //test comparisons == and !=
  m = n;
  bool test1 = m==n;
  bool test2 = m!=n;
  EXPECT_TRUE(test1)<<"Failure ==";
  EXPECT_FALSE(test2)<<"Failure !=";

  n.SetModulus(exp_int::xubint(n.GetModulus()+exp_int::xubint(1)));
  //reset n to a different modulus, comparison will fail.
  test1 = m==n;
  test2 = m!=n;
  EXPECT_FALSE(test1)<<"Failure == different mods";
  EXPECT_TRUE(test2)<<"Failure != different mods";

  // set it back 
  n.SetModulus(n.GetModulus()-exp_int::xubint(1));
  m = n+n;
  test1 = m==n;
  test2 = m!=n;
  EXPECT_FALSE(test1)<<"Failure ==";
  EXPECT_TRUE(test2)<<"Failure !=";

  for (usint i = 0; i < m.GetLength(); i++) {
    m[i] = n[i]; //test both lhs and rhs []
  }

  test1 = m==n;
  EXPECT_TRUE(test1)<<"Failure [] lhs rhs";
}

TEST(UTmubintvec, constructorTest){
  bool dbg_flag = false;
  exp_int::xmubintvec m(10);
  
  m.at(0)="48";
  m.at(1)="53";
  m.at(2)="7";
  m.at(3)="178";
  m.at(4)="190";
  m.at(5)="120";
  m.at(6)="79";
  m.at(7)="108";
  m.at(8)="60";
  m.at(9)="12"; 

  DEBUG("m: "<<m);

  uint64_t expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};  // the expected values are stored as one dimensional integer array

  for (usint i=0;i<10;i++){
    DEBUG("val "<<i<< " is "<<m.at(i));
    EXPECT_EQ (expectedResult[i], (m.at(i)).ConvertToInt());
  }


   exp_int::xmubintvec binvect(m);

  for (usint i=0;i<10;i++){
    EXPECT_EQ (expectedResult[i], (binvect.at(i)).ConvertToInt());
  }
}

TEST(UTmubintvec,mod){

	exp_int::xmubintvec m(10); // calling constructor to create a vector of length 10 zeroed

  size_t i;
	

  //setting value of the value at different index locations
  m.at(0)="987968";
  m.at(1)="587679";
  m.at(2)="456454";
  m.at(3)="234343";
  m.at(4)="769789";
  m.at(5)="465654";
  m.at(6)="79";
  m.at(7)="346346";
  m.at(8)="325328";
  m.at(9)="7698798";	

  exp_int::xubint q("233");		//calling costructor of exp_int::xubint Class to create object for modulus
  //set modulus
  m.SetModulus(q); //should take modulus as well.

  exp_int::xmubintvec calculatedResult = m.Mod(q);
  usint expectedResult[10] = {48,53,7,178,190,120,79,108,60,12};	// the expected values are stored as one dimensional integer array

  for (i=0;i<10;i++) {
    EXPECT_EQ (expectedResult[i], calculatedResult[i].ConvertToUsint());
  }

}

TEST(UTmubintvec,basic_vector_vector_mod_math_1_limb){
  bool dbg_flag = false;

  // q1 modulus 1:
  exp_int::xubint q1("163841");
  // a1:
  exp_int::xmubintvec a1(16,q1);
  DEBUG("a1.modulus "<< a1.GetModulus());
  a1 = { "127753", "077706",
	 "017133", "022582",
	 "112132", "027625",
	 "126773", "008924",
	 "125972", "002551",
	 "113837", "112045",
	 "100953", "077352",
	 "132013", "057029", };

  // b1:
  exp_int::xmubintvec b1;
  b1.SetModulus(q1);
  DEBUG("b1.modulus "<< b1.GetModulus());

  b1 = {"066773", "069572",
	"142134", "141115",
	"123182", "155822",
	"128147", "094818",
	"135782", "030844",
	"088634", "099407",
	"053647", "111689",
	"028502", "026401", };
 
  // modadd1:
  exp_int::xmubintvec modadd1;
  modadd1 = {"030685", "147278",
	     "159267", "163697",
	     "071473", "019606",
	     "091079", "103742",
	     "097913", "033395",
	     "038630", "047611",
	     "154600", "025200",
	     "160515", "083430", };

  modadd1.SetModulus(a1);	// sets modadd1.modulus to the same as a1
  DEBUG("modadd1.modulus "<< modadd1.GetModulus());

  // modsub1:
  std::vector<std::string>  modsub1sv = 
    {"060980", "008134",
     "038840", "045308",
     "152791", "035644",
     "162467", "077947",
     "154031", "135548",
     "025203", "012638",
     "047306", "129504",
     "103511", "030628", };
  exp_int::xmubintvec modsub1(modsub1sv,q1);

  // modmul1:
  std::vector<std::string>  modmul1sv = 
    {"069404", "064196",
     "013039", "115321",
     "028519", "151998",
     "089117", "080908",
     "057386", "039364",
     "008355", "146135",
     "061336", "031598",
     "025961", "087680", };
  exp_int::xmubintvec modmul1(modmul1sv,q1);

  exp_int::xmubintvec c1;
  exp_int::xmubintvec d1;

 //now Mod operations
  c1 = a1.ModAdd(b1);
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector vector ModAdd()";    
  
  DEBUG("modadd1 modulus"<<modadd1.GetModulus());
  DEBUG("c1 modulus"<<c1.GetModulus());
  DEBUG("c1 "<<c1<<" modadd "<<modadd1);

  c1 = a1 + b1;
  EXPECT_EQ (c1, modadd1) << "Failure 1 limb vector vector +";

  d1 = a1;
  d1+=b1;
  EXPECT_EQ (d1, modadd1) << "Failure 1 limb vector vector +=";


  c1 = a1.ModSub(b1);
  EXPECT_EQ (c1, modsub1) << "Failure 1 limb vector vector ModSub()";   

  c1 = a1 - b1;
  EXPECT_EQ (c1, modsub1) << "Failure 1 limb vector vector -";

  d1 = a1;
  d1 -= b1;
  EXPECT_EQ (d1, modsub1) << "Failure 1 limb vector vector -=";

  c1 = a1.ModMul(b1);
  EXPECT_EQ (c1, modmul1) << "Failure 1 limb vector vector ModMul()";   
  c1 = a1 * b1;
  EXPECT_EQ (c1, modmul1) << "Failure 1 limb vector vector *";

  d1 = a1;
  d1 *= b1;
  EXPECT_EQ (d1, modmul1) << "Failure 1 limb vector vector *=";

}
TEST(UTmubintvec,basic_vector_scalar_mod_math_2_limb){
  //basic vector scalar mod math
  //todo this is very simple, should probably add sub mul by bigger numbers.

  // q2:
  exp_int::xubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  
  exp_int::xmubintvec a2(a2sv,q2);
  exp_int::xmubintvec a2op1(a2.GetLength(),q2);
  exp_int::xmubintvec a2op1test(a2.GetLength(),q2);
  
  exp_int::xubint myone(1);
  
  for (usint i = 0; i < a2.GetLength();i ++){
    a2op1[i] = a2[i]+myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModAdd(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar ModAdd()"; 

  for (usint i = 0; i < a2.GetLength();i ++){
    a2op1[i] = a2[i]-myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModSub(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar ModSub()"; 

  for (usint i = 0; i < a2.GetLength();i ++){
    a2op1[i] = a2[i]*myone;
    a2op1[i] %= q2;
  }
  a2op1test = a2.ModMul(myone);
  EXPECT_EQ(a2op1, a2op1test)<< "Failure vector scalar ModMul()"; 

}


TEST(UTmubintvec,basic_vector_vector_mod_math_2_limb){

  // q2 modulus 2:
  exp_int::xubint q2("4057816419532801");
  // a2:
  std::vector<std::string>  a2sv = 
    {"0185225172798255", "0098879665709163",
     "3497410031351258", "4012431933509255",
     "1543020758028581", "0135094568432141",
     "3976954337141739", "4030348521557120",
     "0175940803531155", "0435236277692967",
     "3304652649070144", "2032520019613814",
     "0375749152798379", "3933203511673255",
     "2293434116159938", "1201413067178193", };
  exp_int::xmubintvec a2(a2sv,q2);

  // b2:
  std::vector<std::string>  b2sv = 
    {"0698898215124963", "0039832572186149",
     "1835473200214782", "1041547470449968",
     "1076152419903743", "0433588874877196",
     "2336100673132075", "2990190360138614",
     "0754647536064726", "0702097990733190",
     "2102063768035483", "0119786389165930",
     "3976652902630043", "3238750424196678",
     "2978742255253796", "2124827461185795", };

  exp_int::xmubintvec b2(b2sv,q2);

  // modadd2:
  std::vector<std::string>  modadd2sv = 
    {"0884123387923218", "0138712237895312",
     "1275066812033239", "0996162984426422",
     "2619173177932324", "0568683443309337",
     "2255238590741013", "2962722462162933",
     "0930588339595881", "1137334268426157",
     "1348899997572826", "2152306408779744",
     "0294585635895621", "3114137516337132",
     "1214359951880933", "3326240528363988", };
  exp_int::xmubintvec modadd2(modadd2sv,q2);

  // modsub2:
  std::vector<std::string>  modsub2sv = 
    {"3544143377206093", "0059047093523014",
     "1661936831136476", "2970884463059287",
     "0466868338124838", "3759322113087746",
     "1640853664009664", "1040158161418506",
     "3479109686999230", "3790954706492578",
     "1202588881034661", "1912733630447884",
     "0456912669701137", "0694453087476577",
     "3372508280438943", "3134402025525199", };
  exp_int::xmubintvec modsub2(modsub2sv,q2);

  // modmul2:
  std::vector<std::string>  modmul2sv = 
    {"0585473140075497", "3637571624495703",
     "1216097920193708", "1363577444007558",
     "0694070384788800", "2378590980295187",
     "0903406520872185", "0559510929662332",
     "0322863634303789", "1685429502680940",
     "1715852907773825", "2521152917532260",
     "0781959737898673", "2334258943108700",
     "2573793300043944", "1273980645866111", };
  exp_int::xmubintvec modmul2(modmul2sv,q2);

  exp_int::xmubintvec c2;
  exp_int::xmubintvec d2;

  //now Mod operations
  c2 = a2.ModAdd(b2);
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector vector ModAdd()";    

  c2 = a2 + b2;
  EXPECT_EQ (c2, modadd2) << "Failure 2 limb vector vector +";

  d2 = a2;
  d2 += b2;
  EXPECT_EQ (d2, modadd2) << "Failure 2 limb vector vector +=";
  
  c2 = a2.ModSub(b2);
  EXPECT_EQ (c2, modsub2) << "Failure 2 limb vector vector ModSub()";   

  c2 = a2 - b2;
  EXPECT_EQ (c2, modsub2) << "Failure 2 limb vector vector -";

  d2 = a2;
  d2 -= b2;
  EXPECT_EQ (d2, modsub2) << "Failure 2 limb vector vector -=";
  
  c2 = a2.ModMul(b2);
  EXPECT_EQ (c2, modmul2) << "Failure 2 limb vector vector ModMul()";   

  c2 = a2 * b2;
  EXPECT_EQ (c2, modmul2) << "Failure 2 limb vector vector *";

  d2 = a2;
  d2 *= b2;
  EXPECT_EQ (d2, modmul2) << "Failure 2 limb vector vector *=";

}




TEST(UTmubintvec,basic_vector_vector_mod_math_big_numbers){

  // q3:
  exp_int::xubint q3("3273390607896141870013189696827599152216642046043064789483291368096133796404674554883270092325904157150886684127560071009217256545885393053328527589431");
  exp_int::xmubintvec a3;
  a3 = { 
    "2259002487796164904665772121894078584543401744155154298312726209247751689172189255653866355964200768484575418973864307364757237946940733747446643725054",
    "1478743816308009734668992873633380110912159803397999015955212019971253231528589466789603074746010444199132421555598329082557053986240265071537647362089",
    "2442250766561334341166822783674395133995556495312318016431141348749482739749788174173081312927274880146329980363424977565638001056841245678661782610982",
    "917779106114096279364098211126816308037915672568153320523308800097705587686270523428976942621563981845568821206569141624247183330715577260930218556767",
    "214744931049447103852875386182628152420432967632133352449560778740158135437968557572597545037670326240142368149137864407874100658923913041236510842284",
    "3022931024526554241483841300690432083112912011870712018209552253068347592628043101662926263810401378532416655773738499681026278335470355055192240903881",
    "2177879458107855257699914331737144896274676269055062432826552808869348125407671199582563543692287114712642299482144959316835614426673048987634699368975",
    "297233451802123294436846683552230198845414118375785255038220841170372509047202030175469239142902723134737621108313142071558385068315554041062888072990"};
  a3.SetModulus(q3);
  
  exp_int::xmubintvec b3;
  b3.SetModulus(a3);
  b3 = {
    "1746404952192586268381151521422372143182145525977836700420382237240400642889251297954418325675184427789348433626369450669892557208439401215109489355089",
    "220598825371098531288665964851212313477741334812037568788443848101743931352326362481681721872150902208420539619641973896119680592696228972313317042316",
    "1636408035867347783699588740469182350452165486745277203525427807971352063169622066488977229506420856017031482691439089288020262006748233954177669740311",
    "1391860681743495586446518646883933051685658718352722633694285758474124803847473349064660555618847951719510263829699292297119131926436045214364252430665",
    "840450278810654165061961485691366961514650606247291814263792869596294713810125269780258316551932763106025157596216051681623225968811609560121609943365",
    "2329731862150094912355786583702878434766436140738594274867891494713002534085652731920888891507522355867974791619686673574928137376468103839586921126803",
    "3059472316627396548271906051517665887700234192652488639437431254697285170484189458770168152800520702020313091234437806236204196526193455750117363744648",
    "132216870748476988853044482759545262615616157934129470128771906579101230690441206392939162889560305016204867157725209170345968349185675785497832527174"};


  exp_int::xmubintvec modadd3;
  modadd3.SetModulus(a3);
  modadd3 = {
    "732016832092609303033733946488851575508905224089926209249817078392018535656765998725014589313481039123037168472673687025432538609494741909227605490712",
    "1699342641679108265957658838484592424389901138210036584743655868072997162880915829271284796618161346407552961175240302978676734578936494043850964404405",
    "805268194532540254853221827315978332231079936014530430473277788624701006514735685778788450107791579012474778927303995844441006517704086579510924761862",
    "2309639787857591865810616858010749359723574390920875954217594558571830391533743872493637498240411933565079085036268433921366315257151622475294470987432",
    "1055195209860101268914836871873995113935083573879425166713353648336452849248093827352855861589603089346167525745353916089497326627735522601358120785649",
    "2079272278780507283826438187565711365662706106566241503594152379685216330309021278700545062992019577249504763265865102246737159166053065841450634441253",
    "1963961166839109935958630686427211631758268415664486282780692695470499499487186103469461604166903659582068706589022694543822554406981111684423535524192",
    "429450322550600283289891166311775461461030276309914725166992747749473739737643236568408402032463028150942488266038351241904353417501229826560720600164",
  };

  exp_int::xmubintvec modsub3;
  modsub3.SetModulus(a3);
  modsub3 = {
    "512597535603578636284620600471706441361256218177317597892343972007351046282937957699448030289016340695226985347494856694864680738501332532337154369965",
    "1258144990936911203380326908782167797434418468585961447166768171869509300176263104307921352873859541990711881935956355186437373393544036099224330319773",
    "805842730693986557467234043205212783543391008567040812905713540778130676580166107684104083420854024129298497671985888277617739050093011724484112870671",
    "2799309032266742562930769261070482408568899000258495476312314409719714580243471729247586479328620187276945241504429920336345307950164925099894493715533",
    "2647685260134934808804103597318860343122424407427906327669059277239997218032517842675609320811641720285003894680481883735468131235997696534443428488350",
    "693199162376459329128054716987553648346475871132117743341660758355345058542390369742037372302879022664441864154051826106098140959002251215605319777078",
    "2391797749376600579441197977047078160791084122445638582872412922268196751328156295695665483217670569843215892375267224089848674446364986290845863213758",
    "165016581053646305583802200792684936229797960441655784909448934591271278356760823782530076253342418118532753950587932901212416719129878255565055545816",
  };

  exp_int::xmubintvec modmul3;
  modmul3.SetModulus(a3);
    modmul3 = {
    "1031054745145843056820705945780914118282144310817341310210020640625431998591940403233545109350272933868060509405157360000389345101372898822036359679625",
    "39893990336327654775086201222472749396440031633689107793562292818341559091551650098949141027412374031231642492390533436782802979527602128674296589001",
    "1281575364673380787247887100773933340217543950815953588352031340354110014040347164387450177246143958852636145466379632479296531828035602618716943463922",
    "8876626876958332707488109358602242636976932642794865821404042110211562924605397999217054754859843534043902943791892973269404255881395585577402022234",
    "1216222886905600696846574145744495331189790230286057979942862366975568127231919204120976315097923349074161373380531458334894968146858459205019035261534",
    "753004725575957473234700352714317139479193934162886068369016394155680048439319699359431951178436867519868720662245420487511271148333130090416613227734",
    "2781700410947724700353568488987777429973246834920346616320143955645243949889536315043352628634199412806795883041065539549687937536501039961931401092055",
    "477574462920419903543345320561430691498452711801747910227743781056369739411065806345235440677935972019383967954633150768168291144898135169751571023658",
  };

  exp_int::xmubintvec c3;
  exp_int::xmubintvec d3;
  //now Mod operations
  c3 = a3.ModAdd(b3);
  EXPECT_EQ (c3, modadd3) << "Failure big number vector vector ModAdd()";    

  c3 = a3 + b3;
  EXPECT_EQ (c3, modadd3) << "Failure big number vector vector +";

  d3 = a3;
  d3+=b3;
  EXPECT_EQ (d3, modadd3) << "Failure big number vector vector +=";
  
  c3 = a3.ModSub(b3);
  EXPECT_EQ (c3, modsub3) << "Failure big number vector vector ModSub()";   
  
  c3 = a3 - b3;
  EXPECT_EQ (c3, modsub3) << "Failure big number vector vector -";

  d3 = a3;
  d3 -= b3;
  EXPECT_EQ (d3, modsub3) << "Failure big number vector vector -=";

  c3 = a3.ModMul(b3);
  EXPECT_EQ (c3, modmul3) << "Failure big number vector vector ModMul()";   

  c3 = a3 * b3;
  EXPECT_EQ (c3, modmul3) << "Failure big number vector vector *";

  d3 = a3;
  d3 *= b3;
  EXPECT_EQ (d3, modmul3) << "Failure big number vector vector *=";
  
}

