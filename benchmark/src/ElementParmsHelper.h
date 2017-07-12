/**
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

shared_ptr<ILParams> parm_8_30( new ILParams(8, BigInteger("536871001"), BigInteger("322299632")) );
shared_ptr<ILParams> parm_8_60( new ILParams(8, BigInteger("576460752303423649"), BigInteger("168966263632512486")) );
shared_ptr<ILParams> parm_8_100( new ILParams(8, BigInteger("633825300114114700748351603497"), BigInteger("346785002350981855777149989030")) );
shared_ptr<ILParams> parm_16_30( new ILParams(16, BigInteger("536871089"), BigInteger("453444631")) );
shared_ptr<ILParams> parm_16_60( new ILParams(16, BigInteger("576460752303423649"), BigInteger("445222158767550178")) );
shared_ptr<ILParams> parm_16_100( new ILParams(16, BigInteger("633825300114114700748351603777"), BigInteger("158526154030753428971875578867")) );
shared_ptr<ILParams> parm_32_30( new ILParams(32, BigInteger("536871233"), BigInteger("270599745")) );
shared_ptr<ILParams> parm_32_60( new ILParams(32, BigInteger("576460752303423649"), BigInteger("189737790501446066")) );
shared_ptr<ILParams> parm_32_100( new ILParams(32, BigInteger("633825300114114700748351603777"), BigInteger("548092891331783023532813998227")) );
shared_ptr<ILParams> parm_64_30( new ILParams(64, BigInteger("536871233"), BigInteger("268585022")) );
shared_ptr<ILParams> parm_64_60( new ILParams(64, BigInteger("576460752303426241"), BigInteger("42065371588604318")) );
shared_ptr<ILParams> parm_64_100( new ILParams(64, BigInteger("633825300114114700748351603777"), BigInteger("112238319142051274089073361078")) );
shared_ptr<ILParams> parm_128_30( new ILParams(128, BigInteger("536872321"), BigInteger("536138614")) );
shared_ptr<ILParams> parm_128_60( new ILParams(128, BigInteger("576460752303430529"), BigInteger("285497987503397922")) );
shared_ptr<ILParams> parm_128_100( new ILParams(128, BigInteger("633825300114114700748351608961"), BigInteger("285911309737765344820779602428")) );
shared_ptr<ILParams> parm_256_30( new ILParams(256, BigInteger("536874497"), BigInteger("20558990")) );
shared_ptr<ILParams> parm_256_60( new ILParams(256, BigInteger("576460752303434497"), BigInteger("156313576129429466")) );
shared_ptr<ILParams> parm_256_100( new ILParams(256, BigInteger("633825300114114700748351611393"), BigInteger("357592901114840193907394379371")) );
shared_ptr<ILParams> parm_512_30( new ILParams(512, BigInteger("536874497"), BigInteger("2031030")) );
shared_ptr<ILParams> parm_512_60( new ILParams(512, BigInteger("576460752303436801"), BigInteger("22441747419598564")) );
shared_ptr<ILParams> parm_512_100( new ILParams(512, BigInteger("633825300114114700748351611393"), BigInteger("390541910591016109011030492388")) );
shared_ptr<ILParams> parm_1024_30( new ILParams(1024, BigInteger("536881153"), BigInteger("295184143")) );
shared_ptr<ILParams> parm_1024_60( new ILParams(1024, BigInteger("576460752303436801"), BigInteger("358469952161664325")) );
shared_ptr<ILParams> parm_1024_100( new ILParams(1024, BigInteger("633825300114114700748351634433"), BigInteger("90487631240944978775994429419")) );
shared_ptr<ILParams> parm_2048_30( new ILParams(2048, BigInteger("536881153"), BigInteger("27661536")) );
shared_ptr<ILParams> parm_2048_60( new ILParams(2048, BigInteger("576460752303439873"), BigInteger("227218586376681578")) );
shared_ptr<ILParams> parm_2048_100( new ILParams(2048, BigInteger("633825300114114700748351660033"), BigInteger("538656593806121444004599743100")) );
shared_ptr<ILParams> parm_4096_30( new ILParams(4096, BigInteger("536903681"), BigInteger("316679111")) );
shared_ptr<ILParams> parm_4096_60( new ILParams(4096, BigInteger("576460752303439873"), BigInteger("37211485026155169")) );
shared_ptr<ILParams> parm_4096_100( new ILParams(4096, BigInteger("633825300114114700748351660033"), BigInteger("136971478753003267070551058410")) );
shared_ptr<ILParams> parm_8192_30( new ILParams(8192, BigInteger("536903681"), BigInteger("242542334")) );
shared_ptr<ILParams> parm_8192_60( new ILParams(8192, BigInteger("576460752303439873"), BigInteger("478250159403020681")) );
shared_ptr<ILParams> parm_8192_100( new ILParams(8192, BigInteger("633825300114114700748351660033"), BigInteger("522089389445617342265930548090")) );

shared_ptr<ILParams> parmArray[] = {
parm_8_30,
parm_8_60,
parm_8_100,
parm_16_30,
parm_16_60,
parm_16_100,
parm_32_30,
parm_32_60,
parm_32_100,
parm_64_30,
parm_64_60,
parm_64_100,
parm_128_30,
parm_128_60,
parm_128_100,
parm_256_30,
parm_256_60,
parm_256_100,
parm_512_30,
parm_512_60,
parm_512_100,
parm_1024_30,
parm_1024_60,
parm_1024_100,
parm_2048_30,
parm_2048_60,
parm_2048_100,
parm_4096_30,
parm_4096_60,
parm_4096_100,
parm_8192_30,
parm_8192_60,
parm_8192_100,
};

#define DO_PARM_BENCHMARK(X) \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_30")->Arg(0); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_60")->Arg(1); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_100")->Arg(2); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_30")->Arg(3); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_60")->Arg(4); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_100")->Arg(5); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_30")->Arg(6); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_60")->Arg(7); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_100")->Arg(8); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_30")->Arg(9); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_60")->Arg(10); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_100")->Arg(11); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_30")->Arg(12); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_60")->Arg(13); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_100")->Arg(14); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_30")->Arg(15); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_60")->Arg(16); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_100")->Arg(17); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_30")->Arg(18); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_60")->Arg(19); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_100")->Arg(20); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_30")->Arg(21); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_60")->Arg(22); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_100")->Arg(23); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_30")->Arg(24); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_60")->Arg(25); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_100")->Arg(26); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_30")->Arg(27); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_60")->Arg(28); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_100")->Arg(29); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_30")->Arg(30); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_60")->Arg(31); \
BENCHMARK(X)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_100")->Arg(32); \


#define DO_PARM_BENCHMARK_TEMPLATE(X,Y) \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_30")->Arg(0); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_60")->Arg(1); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8_100")->Arg(2); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_30")->Arg(3); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_60")->Arg(4); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_16_100")->Arg(5); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_30")->Arg(6); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_60")->Arg(7); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_32_100")->Arg(8); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_30")->Arg(9); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_60")->Arg(10); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_64_100")->Arg(11); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_30")->Arg(12); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_60")->Arg(13); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_128_100")->Arg(14); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_30")->Arg(15); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_60")->Arg(16); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_256_100")->Arg(17); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_30")->Arg(18); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_60")->Arg(19); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_512_100")->Arg(20); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_30")->Arg(21); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_60")->Arg(22); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_1024_100")->Arg(23); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_30")->Arg(24); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_60")->Arg(25); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_2048_100")->Arg(26); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_30")->Arg(27); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_60")->Arg(28); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_4096_100")->Arg(29); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_30")->Arg(30); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_60")->Arg(31); \
BENCHMARK_TEMPLATE(X,Y)->Unit(benchmark::kMicrosecond)->ArgName("parm_8192_100")->Arg(32); \


