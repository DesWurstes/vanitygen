#!/bin/bash
cd "$(dirname "$0")"
cd ..
make clean
make vanitygen
make oclvanitygen
mv ./vanitygen-cash ./production-build-utils/Mac
mv ./oclvanitygen-cash ./production-build-utils/Mac
cd production-build-utils
mv Mac VanitygenCash-Mac
zip -r -X VanitygenCash-Mac VanitygenCash-Mac -x VanitygenCash-Mac/.DS_Store
mv VanitygenCash-Mac Mac
cd ..
make clean
rm -f ./production-build-utils/Mac/*vanitygen-cash