# take benchmark snapshot

if [ $# -ne 1 ]
then
	echo Usage is $0 filename-to-store-snapshot
	exit 1
fi

if [ -e $1 ]
then
	echo Sorry, that file already exists
	exit 1
fi

smallbmargs="--benchmark_report_aggregates_only=true --benchmark_format=json"
largebmargs="--benchmark_repetitions=20 --benchmark_report_aggregates_only=true --benchmark_format=json"

echo "running, this will take a while..."

for bm in BBIMath BBVMath NbTheory Lattice 
do
	echo $bm:
	benchmark/bin/${bm}* ${smallbmargs} >> $1
done

for bm in Encoding Crypto SHE
do
	echo $bm:
	benchmark/bin/${bm}* ${largebmargs} >> $1
done

