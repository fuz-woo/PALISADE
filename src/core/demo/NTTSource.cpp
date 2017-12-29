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

// This is a main() file built to test and time NTT operations
// D. Cousins

#define PROFILE //need to define in order to turn on timing
#define TEST1
//#define TEST2
//#define TEST3





#include <iostream>
#include <fstream>
#include <vector>
#include "math/backend.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "utils/inttypes.h"
#include "math/distrgen.h"
#include "encoding/plaintext.h"
#include "time.h"
#include <chrono>
#include <exception>
#include "utils/debug.h"
#include <omp.h> //open MP header

using namespace std;
using namespace lbcrypto;

//define the main sections of the test
void test_NTT(void); 	// test code

//main()   need this for Kurts' makefile to ignore this.
int main(int argc, char* argv[]){
  test_NTT();
  return 0;
}

//Testing macro runs the desired code 
// res = fn
// an a loop nloop times, timed with timer t with res compared to testval

#define TESTIT(t, res, fn, testval, nloop) do {				\
    try {								\
      TIC(t);								\
      for (usint j = 0; j< nloop; j++){					\
	res = (fn);							\
      }									\
      time2 = TOC(t);							\
      DEBUG(#t << ": " << nloop << " loops " << #res << " = " << #fn << " computation time: " << "\t" << time2 << " us"); \
      if (res != testval){						\
	cout << "Bad " << #res << " = " << #fn << endl;			\
	  /*vec_diff(res, testval);*/					\
      }									\
    }catch(exception & e) {cout<< #res << " = " << #fn << " caught exception "<< e.what() <<endl;} \
  } while (0);


//helper function that bulds BigVector from a vector of strings
BigVector BBVfromStrvec( std::vector<std::string> &s) {
  BigVector a(s.size());
  for (usint i = 0; i< s.size(); i++){
    a.at(i)=s[i];
  }
  return a;
}

//function to compare two BigVectors and print differing indicies
void vec_diff(BigVector &a, BigVector &b) {
  for (usint i= 0; i < a.GetLength(); ++i){  
    if (a.at(i) != b.at(i)) {
      cout << "i: "<< i << endl;
      cout << "first vector " <<endl;
      cout << a.at(i);
      cout << endl;
      cout << "second vector " <<endl;
      cout << b.at(i);
      cout << endl;

    }
  }

}

//function to compare two Poly and print differing values
bool clonetest(Poly &a, Poly &b, string name){ 

  if (a != b){
    cout << name <<" FAILED "<<endl;
    cout <<"a:" << a << endl;
    cout <<"b:" << b << endl;
    return true;
  } else {
    return false;
  }
}

//main NTT test suite.
void test_NTT () {

  // Code to test NTT at three different numbers of limbs.

  int nloop = 100; //number of times to run each test for timing.
 
  TimeVar t1,t2, t3,t_total; // timers for TIC() TOC()
  // captures the time
  double time1ar, time1af;
  double time2ar, time2af;
  double time3ar, time3af;

  double time1br, time1bf;
  double time2br, time2bf;
  double time3br, time3bf;

  cout<<"testing NTT backend "<<MATHBACKEND;
  if (BigIntegerBitLength >0)
    cout<<" BITLENGTH "<< BigIntegerBitLength <<endl;

  TIC(t_total);
  //there are three test cases, 1) small modulus 2) approx 48 bits. 
  //3) large numbers and two examples of each 

  //note this fails BigInteger q1 = {"163841"};
  BigInteger q1 ("163841");

  // for each vector, define a, b inputs as vectors of strings
  std::vector<std::string> a1strvec = {
    "127753", "077706",
    "017133", "022582",
    "112132", "027625",
    "126773", "008924",
    "125972", "002551",
    "113837", "112045",
    "100953", "077352",
    "132013", "057029", };

  // this fails too!!! BigVector a1(a1string);
  // so I wrote this function
  BigVector a1 = BBVfromStrvec(a1strvec);
  a1.SetModulus(q1);

  //b:
  std::vector<std::string> b1strvec = 
    { "066773", "069572",
      "142134", "141115",
      "123182", "155822",
      "128147", "094818",
      "135782", "030844",
      "088634", "099407",
      "053647", "111689",
      "028502", "026401", };
  
  BigVector b1  = BBVfromStrvec(b1strvec);
  b1.SetModulus(q1);
  
  //test case 2
  BigInteger q2 ("00004057816419532801");

  std::vector<std::string> a2strvec = {
    "00000185225172798255", "00000098879665709163",
    "00003497410031351258", "00004012431933509255",
    "00001543020758028581", "00000135094568432141",
    "00003976954337141739", "00004030348521557120",
    "00000175940803531155", "00000435236277692967",
    "00003304652649070144", "00002032520019613814",
    "00000375749152798379", "00003933203511673255",
    "00002293434116159938", "00001201413067178193", };

  BigVector a2 = BBVfromStrvec(a2strvec);
  a2.SetModulus(q2);

  std::vector<std::string> b2strvec = 
    { "00000698898215124963", "00000039832572186149",
      "00001835473200214782", "00001041547470449968",
      "00001076152419903743", "00000433588874877196",
      "00002336100673132075", "00002990190360138614",
      "00000754647536064726", "00000702097990733190",
      "00002102063768035483", "00000119786389165930",
      "00003976652902630043", "00003238750424196678",
      "00002978742255253796", "00002124827461185795", };

  BigVector b2 = BBVfromStrvec(b2strvec);
  b2.SetModulus(q2);

  //test case 3

  //q3: very large numbers.
  BigInteger q3("3273390607896141870013189696827599152216642046043064789483291368096133796404674554883270092325904157150886684127560071009217256545885393053328527589431");

  std::vector<std::string> a3strvec = {
    "2259002487796164904665772121894078584543401744155154298312726209247751689172189255653866355964200768484575418973864307364757237946940733747446643725054",
    "1478743816308009734668992873633380110912159803397999015955212019971253231528589466789603074746010444199132421555598329082557053986240265071537647362089",
    "2442250766561334341166822783674395133995556495312318016431141348749482739749788174173081312927274880146329980363424977565638001056841245678661782610982",
    "917779106114096279364098211126816308037915672568153320523308800097705587686270523428976942621563981845568821206569141624247183330715577260930218556767",
    "214744931049447103852875386182628152420432967632133352449560778740158135437968557572597545037670326240142368149137864407874100658923913041236510842284",
    "3022931024526554241483841300690432083112912011870712018209552253068347592628043101662926263810401378532416655773738499681026278335470355055192240903881",
    "2177879458107855257699914331737144896274676269055062432826552808869348125407671199582563543692287114712642299482144959316835614426673048987634699368975",
    "297233451802123294436846683552230198845414118375785255038220841170372509047202030175469239142902723134737621108313142071558385068315554041062888072990"
  };

  BigVector a3 = BBVfromStrvec(a3strvec);
  a3.SetModulus(q3);

  std::vector<std::string> b3strvec = { 
    "1746404952192586268381151521422372143182145525977836700420382237240400642889251297954418325675184427789348433626369450669892557208439401215109489355089",
    "220598825371098531288665964851212313477741334812037568788443848101743931352326362481681721872150902208420539619641973896119680592696228972313317042316",
    "1636408035867347783699588740469182350452165486745277203525427807971352063169622066488977229506420856017031482691439089288020262006748233954177669740311",
    "1391860681743495586446518646883933051685658718352722633694285758474124803847473349064660555618847951719510263829699292297119131926436045214364252430665",
    "840450278810654165061961485691366961514650606247291814263792869596294713810125269780258316551932763106025157596216051681623225968811609560121609943365",
    "2329731862150094912355786583702878434766436140738594274867891494713002534085652731920888891507522355867974791619686673574928137376468103839586921126803",
    "3059472316627396548271906051517665887700234192652488639437431254697285170484189458770168152800520702020313091234437806236204196526193455750117363744648",
    "132216870748476988853044482759545262615616157934129470128771906579101230690441206392939162889560305016204867157725209170345968349185675785497832527174"
  };

  BigVector b3 = BBVfromStrvec(b3strvec);
  b3.SetModulus(q3);

#if 1
  usint m = 32;

  //  BigInteger modulus(q1);

  //  NextQ(modulus, BigInteger("2"), m1, BigInteger("4"), BigInteger("4"));
#ifdef TEST1 
  BigInteger rootOfUnity1(RootOfUnity<BigInteger>(m, q1));
  ILParams params1(m, q1, rootOfUnity1);
  shared_ptr<ILParams> x1p(new ILParams(params1));

  Poly x1a(x1p, Format::COEFFICIENT);
  //a1.SetModulus(modulus); //note setting modulus does not perform a modulus.
  //a1.Mod(modulus);
  x1a.SetValues(a1, Format::COEFFICIENT);

  Poly x1b(x1p, Format::COEFFICIENT);
  //b1.SetModulus(modulus);
  //b1.Mod(modulus);
  x1b.SetValues(b1, Format::COEFFICIENT);

  Poly x1aClone(x1a);
  Poly x1bClone(x1b);
#endif
#ifdef TEST2
  BigInteger rootOfUnity2(RootOfUnity<BigInteger>(m, q2));
  ILParams params2(m, q2, rootOfUnity2);
  shared_ptr<ILParams> x2p(new ILParams(params2));

  Poly x2a(x2p, Format::COEFFICIENT);
  //a2.SetModulus(modulus); //note setting modulus does not perform a modulus.
  //a2.Mod(modulus);
  x2a.SetValues(a2, Format::COEFFICIENT);

  Poly x2b(x2p, Format::COEFFICIENT);
  //b2.SetModulus(modulus);
  //b2.Mod(modulus);
  x2b.SetValues(b2, Format::COEFFICIENT);

  Poly x2aClone(x2a);
  Poly x2bClone(x2b);
#endif  
#ifdef TEST3
  NextQ(q3, BigInteger("2"), m, BigInteger("4"), BigInteger("4"));
  cout << "q3 : "<<q3.ToString()<<endl;

  BigInteger rootOfUnity3(RootOfUnity<BigInteger>(m, q3));
  cout << "rootOfUnity3 : "<<rootOfUnity3.ToString()<<endl;
  ILParams params3(m, q3, rootOfUnity3);
  shared_ptr<ILParams> x3p(new ILParams(params3));

  Poly x3a(x3p, Format::COEFFICIENT);
  //a3.SetModulus(modulus); //note setting modulus does not perform a modulus.
  //a3.Mod(modulus);
  x3a.SetValues(a3, Format::COEFFICIENT);

  Poly x3b(x3p, Format::COEFFICIENT);
  //b3.SetModulus(modulus);
  //b3.Mod(modulus);
  x3b.SetValues(b3, Format::COEFFICIENT);

  Poly x3aClone(x3a);
  Poly x3bClone(x3b);
#endif

  time1af = 0.0;
  time1bf = 0.0;

  time2af = 0.0;
  time2bf = 0.0;

  time3af = 0.0;
  time3bf = 0.0;

  time1ar = 0.0;
  time1br = 0.0;

  time2ar = 0.0;
  time2br = 0.0;

  time3ar = 0.0;
  time3br = 0.0;


  bool failed = false;
  int ix;
  cout << "Startng timing"<<endl;

  for (ix = 0; ix <nloop; ix++) {
    if (ix%100 == 0)
      cout << ix <<endl;
#ifdef TEST1    
    //forward 
    TIC(t1);
    x1a.SwitchFormat();
    time1af += TOC_US(t1);

    TIC(t1);
    x1b.SwitchFormat();
    time1bf += TOC_US(t1);
#endif
#ifdef TEST2    
    TIC(t1);
    x2a.SwitchFormat();
    time2af += TOC_US(t1);

    TIC(t1);
    x2b.SwitchFormat();
    time2bf += TOC_US(t1);
#endif
#ifdef TEST3
    TIC(t1);
    x3a.SwitchFormat();
    time3af += TOC_US(t1);

    TIC(t1);
    x3b.SwitchFormat();
    time3bf += TOC_US(t1);
#endif
#ifdef TEST1    //reverse
    TIC(t1);
    x1a.SwitchFormat();
    time1ar += TOC_US(t1);

    TIC(t1);
    x1b.SwitchFormat();
    time1br += TOC_US(t1);
#endif
#ifdef TEST2
    TIC(t1);
    x2a.SwitchFormat();
    time2ar += TOC_US(t1);

    TIC(t1);
    x2b.SwitchFormat();
    time2br += TOC_US(t1);
#endif
#ifdef TEST3
    TIC(t1);
    x3a.SwitchFormat();
    time3ar += TOC_US(t1);

    TIC(t1);
    x3b.SwitchFormat();
    time3br += TOC_US(t1);
#endif
#ifdef TEST1
    failed |= clonetest(x1a, x1aClone, "x1a");
    failed |= clonetest(x1b, x1bClone, "x1b");
#endif
#ifdef TEST2
    failed |= clonetest(x2a, x2aClone, "x2a");
    failed |= clonetest(x2b, x2bClone, "x2b");
#endif
#ifdef TEST3
    failed |= clonetest(x3a, x3aClone, "x3a");
    failed |= clonetest(x3b, x3bClone, "x3b");
#endif

  }

  if (failed) {
    cout << "failure in loop number "<< ix<<endl;
  } else {
    
    time1af/=(double)nloop;
    time1bf/=(double)nloop;
    time2af/=(double)nloop;
    time2bf/=(double)nloop;
    time3af/=(double)nloop;
    time3bf/=(double)nloop;
    
    time1ar/=(double)nloop;
    time1br/=(double)nloop;
    time2ar/=(double)nloop;
    time2br/=(double)nloop;
    time3ar/=(double)nloop;
    time3br/=(double)nloop;
    
    
    cout << nloop << " loops"<<endl;
    cout << "t1af: "  << "\t" << time1af << " us"<< endl;
    cout << "t1bf: " << "\t" << time1bf << " us"<< endl;
    
    cout << "t2af: " << "\t" << time2af << " us"<< endl;
    cout << "t2bf: " << "\t" << time2bf << " us"<< endl;
    
    cout << "t3af: " << "\t" << time3af << " us"<< endl;
    cout << "t3bf: " << "\t" << time3bf << " us"<< endl;

    cout << "t1ar: " << "\t" << time1ar << " us"<< endl;
    cout << "t1br: " << "\t" << time1br << " us"<< endl;
    
    cout << "t2ar: " << "\t" << time2ar << " us"<< endl;
    cout << "t2br: " << "\t" << time2br << " us"<< endl;
    
    cout << "t3ar: " << "\t" << time3ar << " us"<< endl;
    cout << "t3br: " << "\t" << time3br << " us"<< endl;
  }
#endif  
  return ;
}


