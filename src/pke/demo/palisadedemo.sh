# args get passed into first keygenner
# like: -dcrt -use BFVrns1
# or:	-poly -use Null

# first arg needs to be -poly or -dcrt

ELEMENT=$1
shift

rm -f HEDEMOPUB HEDEMOPRI HEDEMOCTXT HEDEMOEMK CT1 CT2 CTSum CTProd PTSum PTProd
echo Inputs:
cat myints1
cat myints2
bin/demo/pke/palisade $ELEMENT $* makekey HEDEMO
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO encrypt myints1 HEDEMOPUB CT1
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO encrypt myints2 HEDEMOPUB CT2
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO evaladd CT1 CT2 CTSum
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO evalmult CT1 CT2 CTProd
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO decrypt CTProd HEDEMOPRI PTProd
bin/demo/pke/palisade $ELEMENT -integers -from HEDEMO decrypt CTSum HEDEMOPRI PTSum

echo ; echo Sum:
cat PTSum
echo ; echo Product:
cat PTProd
