#!/bin/bash
cd "$(dirname "$0")"
cd ..
make clean
make vanitygen
make oclvanitygen
mv ./vanitygen-cash ./production-build-utils/Linux
mv ./oclvanitygen-cash ./production-build-utils/Linux
cd production-build-utils
mv Linux VanitygenCash-Linux
zip -r -X VanitygenCash-Linux VanitygenCash-Linux -x VanitygenCash-Linux/.DS_Store
mv VanitygenCash-Linux Linux
cd ..
make clean
rm -f ./production-build-utils/Linux/*vanitygen-cash