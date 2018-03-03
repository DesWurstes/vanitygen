#!/bin/bash
# Arg1 = "Mac" or "Linux"
cd "$(dirname "$0")"
cd ..
make clean
make all
cd production-build-utils
mv ../vanitygen-cash $1
mv ../oclvanitygen-cash $1
mv ../oclvanitygen-cash $1
mv ../calc_addrs.cl $1
mv ../LICENSE $1
mv resources/pcre_license.txt $1
mv resources/openssl_license.txt $1
mv $1 VanitygenCash-$1
rm -f VanitygenCash-$1.zip
zip -r -X VanitygenCash-$1 VanitygenCash-$1 -x VanitygenCash-$1/.DS_Store
mv VanitygenCash-$1 $1
mv $1/pcre_license.txt resources
mv $1/openssl_license.txt resources
mv $1/calc_addrs.cl ../
mv $1/LICENSE ../
cd ..
make clean
rm -f production-build-utils/$1/*vanitygen-cash
