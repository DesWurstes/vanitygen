#!/bin/bash
cd "$( dirname "$0" )"
find . -type f -name \*.o -delete
find . -type f -name \*vanitygen-cash -delete
find . -type f -name keyconv -delete
find . -type f -name \*.oclbin -delete
find . -type f -name \*miner -delete
rm -rf vanitygen-cash.dSYM
rm -rf keyconv.dSYM
rm -rf oclvanitygen-cash.dSYM
rm -rf oclvanityminer.dSYM
