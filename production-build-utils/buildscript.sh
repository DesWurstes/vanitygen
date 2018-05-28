#!/bin/bash
# Arg1 = "Mac" or "Linux"
cd "$(dirname "$0")"
cd ..
make clean
make static_$1
make static_$1_ocl
cd production-build-utils
mv ../static_vanitygen-cash $1/vanitygen-cash
mv ../static_oclvanitygen-cash $1/oclvanitygen-cash
mv ../calc_addrs.cl $1
mv ../LICENSE $1
mv resources/hyperscan_license.txt $1
mv resources/openssl_license.txt $1
mv resources/polymod_license.txt $1
mv $1 VanitygenCash-$1
rm -f VanitygenCash-$1.zip
zip -r -X VanitygenCash-$1 VanitygenCash-$1 -x VanitygenCash-$1/.DS_Store
mv VanitygenCash-$1 $1
mv $1/hyperscan_license.txt resources
mv $1/openssl_license.txt resources
mv $1/polymod_license.txt resources
mv $1/calc_addrs.cl ../
mv $1/LICENSE ../
cd ..
make clean
rm -f production-build-utils/$1/*vanitygen-cash
