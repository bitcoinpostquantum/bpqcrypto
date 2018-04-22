#!/bin/bash

DOCKER_IMAGE=quay.io/pypa/manylinux1_x86_64

chmod +x build_linux.bash

docker run --rm -v `pwd`/..:/io $DOCKER_IMAGE $PRE_CMD/io/python/build_linux.bash
