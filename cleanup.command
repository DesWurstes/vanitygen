#!/bin/bash
cd "$( dirname "$0" )"
find . -type f -name \*.o -delete
find . -type f -name \*vanitygen -delete
find . -type f -name keyconv -delete
find . -type f -name \*.oclbin -delete
rm -rf vanitygen.dSYM
rm -rf keyconv.dSYM
rm -rf oclvanitygen.dSYM
