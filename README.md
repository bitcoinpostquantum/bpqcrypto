
# bpqcrypto library


## requirements to build:

cmake

```
apt-get install cmake
```

python3

```
apt-get install python3 python3-pip
pip3 install setuptools wheel
```


# Build library

mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=stage
cmake --build . --target=install --config=Release


# Build package

## for windows

```
cp build/stage/bpqcrypto.dll python/bpqcrypto
cd python
python3 setup.py bdist_wheel
mv dist/bpqcrypto-1.0.0-cp35-cp35m-win_amd64.whl dist/bpqcrypto-1.0.0-py3-none-win_amd64.whl
```

## for linux

```
cp build/stage/libbpqcrypto.so python/bpqcrypto
cd python
python3 setup.py bdist_wheel
mv dist/bpqcrypto-1.0.0-cp36-cp36m-win_amd64.whl dist/bpqcrypto-1.0.0-py3-none-manylinux1_x86_64.whl
```

or use docker with CentOS5 to build.
```
cd python
./run.sh
```

# install package

## from pypi
pip3 install bpqcrypto

## from wheel
### for windows
```
pip3 install bpqcrypto-1.0.2-py3-none-win_amd64.whl
```
### for linux
```
pip3 install bpqcrypto-1.0.0-py3-none-manylinux1_x86_64.whl
```

## test

```
python3 -m bpqcrypto.test
```

## remove package

```
pip3 uninstall bpqcrypto-1.0.0-cp35-cp35m-win_amd64.whl
```

## packages for windows
```
mv bpqcrypto-1.0.1-cp35-cp35m-win_amd64.whl bpqcrypto-1.0.1-py3-none-win_amd64.whl
```
