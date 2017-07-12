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
  This code exercises the random number distribution generator libraries
  of the PALISADE lattice encryption library.

  4/22/2016 DBC: modified to new UT format. Adding validity checks for parallelization code.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "math/backend.h"
#include "utils/inttypes.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "math/distrgen.h"
#include "lattice/poly.h"
#include "math/nbtheory.h"
#include "lattice/elemparams.h"
#include "lattice/ilelement.h"
#include "utils/utilities.h"
#include "utils/debug.h"

#include <omp.h>

#include "../lib/lattice/dcrtpoly.h"
using namespace std;
using namespace lbcrypto;

/*
  int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
  }
*/
class UnitTestDistrGen : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};
//////////////////////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteUniformGenerator
//////////////////////////////////////////////////////////////////

// helper functions defined later
void testDiscreteUniformGenerator(BigInteger &modulus, std::string test_name);
void testParallelDiscreteUniformGenerator(BigInteger &modulus, std::string test_name);


TEST(UTDistrGen, DiscreteUniformGenerator_LONG ) {

  // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH SMALL MODULUS
  {
    BigInteger modulus("10403");
    Poly::DugType dug = Poly::DugType();
    dug.SetModulus(modulus);
    BigInteger uniRandNum = dug.GenerateInteger();

    EXPECT_LT(uniRandNum, modulus) << "Failure testing with_in_small_modulus_integer_small_modulus";
  }

  // TEST CASE TO GENERATE A UNIFORM BIG BINARY INTEGER WITH LARGE MODULUS
  if( MATH_DEFBITS > 64 ) {
    BigInteger modulus("10402635286389262637365363");
    Poly::DugType dug = Poly::DugType();
    dug.SetModulus(modulus);
    BigInteger uniRandNum = dug.GenerateInteger();

    EXPECT_LT(uniRandNum, modulus) << "Failure testing with_in_large_modulus_integer_large_modulus";
  }

  //TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH SMALL MODULUS
  {
    BigInteger modulus("10403");
    Poly::DugType dug = Poly::DugType();
    dug.SetModulus(modulus);
    
    usint size = 10;
    BigVector uniRandVector = dug.GenerateVector(size);
    // test length
    EXPECT_EQ(uniRandVector.GetLength(), size) << "Failure testing vector_uniform_vector_small_modulus wrong length";
    // test content
    for(size_t i=0; i<size; i++) {
      EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus)
	<< "Failure testing vector_uniform_vector_small_modulus value greater than modulus at index "<< i;
    }
  }
  
  //TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS
  
  if( MATH_DEFBITS > 64 ) {
    BigInteger modulus("10402635286389262637365363");
    Poly::DugType dug = Poly::DugType();
    dug.SetModulus(modulus);

    usint size = 100;
    BigVector uniRandVector = dug.GenerateVector(size);
    // test length
    EXPECT_EQ(uniRandVector.GetLength(), size) << "Failure testing vector_uniform_vector_large_modulus";
    // test content
    for(size_t i=0; i<size; i++) {
      EXPECT_LT(uniRandVector.GetValAtIndex(i), modulus) 
	<< "Failure testing vector_uniform_vector_large_modulus value greater than modulus at index "<< i;
    }
  }

  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS SMALL MODULUS
    BigInteger small_modulus("7919");
    testDiscreteUniformGenerator(small_modulus, "small_modulus");
  }
  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS LARGE MODULUS
    BigInteger large_modulus("100019");
    testDiscreteUniformGenerator(large_modulus, "large_modulus");
  }
  if( MATH_DEFBITS > 64 ) {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS HUGE MODULUS
    BigInteger huge_modulus("10402635286389262637365363");
    testDiscreteUniformGenerator(huge_modulus, "huge_modulus");
  }

  //TEST CASE TO RECREATE OVERFLOW ISSUE CAUSED WHEN CALCULATING MEAN OF BBI's
  //Issue#73
  if( MATH_DEFBITS > 64 ) {
    int caught_error = 0;
    try {
      BigInteger modulus("10402635286389262637365363"); //10402635286389262637365363
      Poly::DugType dug = Poly::DugType();
      dug.SetModulus(modulus);

      usint eachIterationSize = 1000, noOfIterations = 100;
      BigInteger sum, mean, N(eachIterationSize);
	
      BigVector uniRandVector = dug.GenerateVector(eachIterationSize * noOfIterations);
	
      for(usint i=0; i<noOfIterations; i++) {
	sum = mean = BigInteger(0);
	for(size_t j=i*eachIterationSize; j<(i+1)*eachIterationSize; j++) {
	  sum += uniRandVector.GetValAtIndex(j);
	}
	mean = sum.DividedBy(N);
      }
    }
    catch (...) {
      caught_error = 1;
    }
    EXPECT_EQ(caught_error, 0)<< "Failure recreate_overflow_issue threw an error";
  } 
} //end TEST(UTDistrGen, DiscreteUniformGenerator)

//
// helper function to test first and second central moment of discrete uniform generator
// single thread case
void testDiscreteUniformGenerator(BigInteger &modulus, std::string test_name){
  // TEST CASE ON FIRST CENTRAL MOMENT

    double modulusInDouble = modulus.ConvertToDouble();
    double expectedMeanInDouble = modulusInDouble / 2.0;

    Poly::DugType distrUniGen = Poly::DugType();
    distrUniGen.SetModulus(modulus);

    usint size = 50000;
    BigVector randBigVector = distrUniGen.GenerateVector(size);

    double sum=0;
    BigInteger length(std::to_string(randBigVector.GetLength()));

    for(usint index=0; index<size; index++) {
      sum += (randBigVector.GetValAtIndex(index)).ConvertToDouble();
    }

    double computedMeanInDouble = sum/size;
    double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);

    //within 1% of expected mean
    EXPECT_LT(diffInMeans, 0.01*modulusInDouble) << 
      "Failure testing first_moment_test_convertToDouble " << test_name;


    // TEST CASE ON SECOND CENTRAL MOMENT
    double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0;
    double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);

    sum=0;
    double temp;
    for(usint index=0; index<size; index++) {
      temp = (randBigVector.GetValAtIndex(index)).ConvertToDouble() - expectedMeanInDouble;
      temp *= temp;
      sum += temp;
    }

    double computedVariance = (sum/size);
    double computedStdDev = sqrt(computedVariance);
    double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);

    EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble) << 
      "Failure testing second_moment_test_convertToDouble "<< test_name;
}


TEST(UTDistrGen, ParallelDiscreteUniformGenerator_LONG ) {

  //BUILD SEVERAL VECTORS OF BBI IN PARALLEL, CONCATENATE THEM TO ONE LARGE VECTOR AND TEST
  //THE RESULT OF THE FIRST AND SECOND CENTRAL MOMENTS

  BigInteger small_modulus("7919"); // test small modulus
  testParallelDiscreteUniformGenerator(small_modulus, "small_modulus");

  BigInteger large_modulus("100019");// test large modulus
  testParallelDiscreteUniformGenerator(large_modulus, "large_modulus");

  if( MATH_DEFBITS > 64 ) {
	  BigInteger huge_modulus("10402635286389262637365363");
	  testParallelDiscreteUniformGenerator(huge_modulus, "huge_modulus");
  }

}

//
// helper function to test first and second central moment of discrete uniform generator
// multi thread case
void testParallelDiscreteUniformGenerator(BigInteger &modulus, std::string test_name){
  double modulusInDouble = modulus.ConvertToDouble();
  // we expect the mean to be modulus/2 (the mid range of the min-max data);
  double expectedMeanInDouble = modulusInDouble / 2.0;
  usint size = 50000;
  //usint size = omp_get_max_threads() * 4;

  bool dbg_flag = false;
  vector <BigInteger> randBigVector;
#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <BigInteger> randBigVectorPvt;
    Poly::DugType distrUniGen = Poly::DugType();
    distrUniGen.SetModulus(modulus);
    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      randBigVectorPvt.push_back(distrUniGen.GenerateInteger());
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
    	{
      DEBUG("thread #" << omp_get_thread_num() << " moving "
	    << (int)randBigVectorPvt.size()  << " to starting point "
	    << (int)randBigVector.size() );
      randBigVector.insert(randBigVector.end(), randBigVectorPvt.begin(), randBigVectorPvt.end());
      DEBUG("thread #" << omp_get_thread_num() << " moved");
    	}
    }

  }

  // now compute the sum over the entire vector
  double sum = 0;
  BigInteger length(std::to_string(randBigVector.size()));
  
  for(usint index=0; index<size; index++) {
    sum += (randBigVector[index]).ConvertToDouble();
  }
  // divide by the size (i.e. take mean)
  double computedMeanInDouble = sum/size;
  // compute the difference between the expected and actual
  double diffInMeans = abs(computedMeanInDouble - expectedMeanInDouble);
  
  //within 1% of expected mean
  EXPECT_LT(diffInMeans, 0.01*modulusInDouble) << "Failure testing parallel_first_central_moment_test " << test_name;
  
  // TEST CASE ON SECOND CENTRAL MOMENT SMALL MODULUS
  double expectedVarianceInDouble = ((modulusInDouble - 1.0)*(modulusInDouble - 1.0))/12.0; // var = ((b-a)^2) /12
  double expectedStdDevInDouble = sqrt(expectedVarianceInDouble);
  
  sum=0;
  double temp;
  for(usint index=0; index<size; index++) {
    temp = (randBigVector[index]).ConvertToDouble() - expectedMeanInDouble;
    temp *= temp;
    sum += temp;
  }
  
  double computedVariance = (sum/size);
  double computedStdDev = sqrt(computedVariance);
  
  double diffInStdDev = abs(computedStdDev - expectedStdDevInDouble);
  
  //within 1% of expected std dev
  EXPECT_LT(diffInStdDev, 0.01*expectedStdDevInDouble) << "Failure testing second_central_moment_test " << test_name;
}

// TEST(UTDistrGen, DiscreteUniformGeneratorSeed ) {
//   BigInteger modulus("7919"); // test small modulus
//   double sum1=0;
//   usint size = 10;
//   {
//     DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus, 12345);
  
//     BigVector randBigVector1 = distrUniGen.GenerateVector(size);
  
  
//     for(usint index=0; index<size; index++) {
//       sum1 += (randBigVector1.GetValAtIndex(index)).ConvertToDouble();
//     }
//   }
//   DiscreteUniformGenerator distrUniGen = lbcrypto::DiscreteUniformGenerator(modulus, 12345);
//   BigVector randBigVector2 = distrUniGen.GenerateVector(size);
//   double sum2=0;

//   for(usint index=0; index<size; index++) {
//     sum2 += (randBigVector2.GetValAtIndex(index)).ConvertToDouble();
//   }
  
//   EXPECT_EQ(sum1, sum2) << "Failure, summs are different";
  
// }


////////////////////////////////////////////////
// Testing Methods of BigInteger BinaryUniformGenerator
////////////////////////////////////////////////


 TEST(UTDistrGen, BinaryUniformGenerator ) {


  // fail if less than 0
  {
    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
    BigInteger binUniRandNum = binaryUniGen.GenerateInteger();
    EXPECT_GE(binUniRandNum.ConvertToInt(), 0ULL)
      << "Failure less than 0";
  }

  // fail if gt 1
  {
    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();
    BigInteger binUniRandNum = binaryUniGen.GenerateInteger();
    EXPECT_LE(binUniRandNum.ConvertToInt(), 1ULL)
      << "Failure greater than 1";
  }

  // mean test
  {

    BinaryUniformGenerator binaryUniGen = lbcrypto::BinaryUniformGenerator();

    usint length = 100000;
    BigInteger modulus = BigInteger("1041");
    BigVector randBigVector = binaryUniGen.GenerateVector(length, modulus);

    usint sum = 0;

    for(usint index=0; index<randBigVector.GetLength(); index++) {
      sum += randBigVector.GetValAtIndex(index).ConvertToInt();
    }
    //std::cout << "Observed sum is " << sum << std::endl;
    //std::cout << "Length is " << length << std::endl;
    float computedMean = (float)sum/(float)length;
    //std::cout << "The computedMean is " << computedMean << std::endl;
    float expectedMean = 0.5;
    float dif = abs(computedMean-expectedMean);
    //std::cout << "The difference is " << dif << std::endl;

    //std::cout << "Running Test." << std::endl;
    EXPECT_LT(dif,0.01)
      << "Failure Mean is incorrect";
    // a large sample. Max of them should be less than q

  }
} // end TEST(

 // mean test
 TEST(UTDistrGen, TernaryUniformGenerator) {
	 
	 TernaryUniformGenerator ternaryUniGen = lbcrypto::TernaryUniformGenerator();

	 usint length = 100000;
	 BigInteger modulus = BigInteger("1041");
	 BigVector randBigVector = ternaryUniGen.GenerateVector(length, modulus);

	 int32_t sum = 0;

	 for (usint index = 0; index<randBigVector.GetLength(); index++) {
		 if (randBigVector[index] == modulus - 1)
			 sum -= 1;
		 else
			 sum += randBigVector[index].ConvertToInt();
	 }

	 float computedMean = (double)sum / (double)length;

	 float expectedMean = 0;
	 float dif = abs(computedMean - expectedMean);

	 //std::cout << "Running Test." << std::endl;
	 EXPECT_LT(dif, 0.01)
		 << "Ternary Uniform Distribution Failure Mean is incorrect";
	 // a large sample. Max of them should be less than q

 }


////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteGaussianGenerator
////////////////////////////////////////////////


TEST(UTDistrGen, DiscreteGaussianGenerator) {
  //mean test

  {
    std::cout<<"note this sometimes fails. are limits set correctly?"<<std::endl;
    sint stdev = 5;
    usint size = 10000;
    BigInteger modulus("10403");
    const DiscreteGaussianGenerator& dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    std::shared_ptr<sint> dggCharVector = dgg.GenerateIntVector(size);

    double mean = 0;
    for(usint i=0; i<size; i++) {
      mean += (double) (dggCharVector.get())[i];
      // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
    }
    mean /= size;
    // std::cout << "The mean of the values is " << mean << std::endl;

    EXPECT_LE(mean, 0.1) << "Failure generate_char_vector_mean_test mean > 0.1";
    EXPECT_GE(mean, -0.1) << "Failure generate_char_vector_mean_test mean < -0.1";;
  }

  // generate_vector_mean_test
  {
    sint stdev = 5;
    usint size = 100000;
    BigInteger modulus("10403");
    BigInteger modulusByTwo(modulus.DividedBy(2));
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    BigVector dggBigVector = dgg.GenerateVector(size,modulus);

    usint countOfZero = 0;
    double mean = 0, current = 0;

    for(usint i=0; i<size; i++) {
      current = std::stod(dggBigVector.GetValAtIndex(i).ToString());
      if(current == 0)
	countOfZero++;
      mean += current;
    }

    mean /= (size - countOfZero);
    // std::cout << "The mean of the values is " << mean << std::endl;

    double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

    double diff = abs(modulusByTwoInDouble - mean);
    EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";
  }

}


TEST(UTDistrGen, ParallelDiscreteGaussianGenerator_VERY_LONG) {
  //mean test
  bool dbg_flag = false;

  {
    sint stdev = 5;
    usint size = 10000;
    BigInteger modulus("10403");


    vector<sint>dggCharVector;
    //    sint* dggCharVector = dgg.GenerateIntVector(size);

#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <sint> dggCharVectorPvt;
    const DiscreteGaussianGenerator& dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      dggCharVectorPvt.push_back(dgg.GenerateInt());
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
    	{
      DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
	    << (int)dggCharVectorPvt.size()  << " to starting point" 
	    << (int)dggCharVector.size() );
      dggCharVector.insert(dggCharVector.end(), dggCharVectorPvt.begin(), dggCharVectorPvt.end());
    	}
    }

  }

  double mean = 0;
  for(usint i=0; i<size; i++) {
    mean += (double) dggCharVector[i];
    // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
  }
    mean /= size;
    // std::cout << "The mean of the values is " << mean << std::endl;
    
    EXPECT_LE(mean, 0.1) << "Failure parallel generate_char_vector_mean_test mean > 0.1";
    EXPECT_GE(mean, -0.1) << "Failure parallel generate_char_vector_mean_test mean < -0.1";;
  }

  // generate_vector_mean_test
  {
    sint stdev = 5;
    usint size = 100000;
    BigInteger modulus("10403");
    BigInteger modulusByTwo(modulus.DividedBy(2));
    //BigVector dggBigVector = dgg.GenerateVector(size,modulus);
    vector<BigInteger> dggBigVector;
#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    vector <BigInteger> dggBigVectorPvt;
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

    // build the vectors in parallel
#pragma omp for nowait schedule(static)
    for(usint i=0; i<size; i++) {
      //build private copies in parallel
      dggBigVectorPvt.push_back(dgg.GenerateInteger(modulus));
    }
    
#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
    	{
      DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
	    << (int)dggBigVectorPvt.size()  << " to starting point" 
	    << (int)dggBigVector.size() );
      dggBigVector.insert(dggBigVector.end(), dggBigVectorPvt.begin(), dggBigVectorPvt.end());
    	}
    }
  }

    usint countOfZero = 0;
    double mean = 0, current = 0;

    for(usint i=0; i<size; i++) {
      current = std::stod(dggBigVector[i].ToString());
      if(current == 0)
	countOfZero++;
      mean += current;
    }

    mean /= (size - countOfZero);
    // std::cout << "The mean of the values is " << mean << std::endl;

    double modulusByTwoInDouble = std::stod(modulusByTwo.ToString());

    double diff = abs(modulusByTwoInDouble - mean);
    EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";
  }

}
