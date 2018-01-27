#!/bin/bash
cd "$( dirname "$0" )"
find . -type f -name \*.o -delete
find . -type f -name vanitygen -delete
rm -rf vanitygen.dSYM
rm -rf keyconv.dSYM