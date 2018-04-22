#!/bin/bash

# build library

mkdir -p build

cd build

cmake .. -DCMAKE_INSTALL_PREFIX=stage
make && make install || exit 1

# create package

cp stage/*.so  ../python/bpqcrypto

cd ../python

python3 ./setup.py bdist_wheel

