echo Welcome to PALISADE
echo This tool checks to see if you can run palisade in your environment,
echo and tells you what tools you may need

KernelName=`uname -s`

echo OS is $OS
echo Kernel is $KernelName
echo

##### REQUIRED
### Compiler suite that supports C++11
if [ "$OS" = "Windows_NT" ]
then
	CC="g++ -std=gnu++11"
elif [ "$KernelName" = "Linux" ]
then
	CC="g++ -std=gnu++11"
elif [ "$KernelName" = "Darwin" ]
then
	CC="clang++ -std=c++11"
else
	echo $OS and $KernelName are not supported
	exit 1
fi

$CC -v >/dev/null 2>&1
[ $? -ne 0 ] && echo Compiler is not available && exit 1

($CC -x c++ -o ./__test - <<XXX--end
#if __cplusplus < 201103L
#error This library requires a C++11 compliant compiler
#endif
int main() { return 0; }
XXX--end
) && ./__test && rm -f ./__test

[ $? -ne 0 ] && echo Compiler does not support C++11 && exit 1

echo Compiler OK

### make

make -v >/dev/null 2>&1

[ $? -ne 0 ] && echo make is not installed && exit 1

echo make is installed

### flex

flex --version >/dev/null 2>&1

[ $? -ne 0 ] && echo flex is not installed && exit 1

echo flex is installed

### bison

bison --version >/dev/null 2>&1

[ $? -ne 0 ] && echo bison is not installed && exit 1

echo bison is installed

### Open MP

($CC -x c++ -o ./__test -fopenmp - <<XXX--end
#include <omp.h>
int main() {
#pragma omp parallel
{
int t = omp_get_thread_num();
}
return 0;
}
XXX--end
) && ./__test && rm -f ./__test

[ $? -ne 0 ] && echo Environment does not support OpenMP && exit 1

echo OpenMP OK

### 128 bit unsigned int if you want native

	MINGWREGEX="-Lc:/Mingw64/mingw64/opt/lib -lregex -lshlwapi"

	OMPINCLUDE="-I /opt/local/include/libomp -fopenmp"
