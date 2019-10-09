#!/usr/bin/sh

BUILD_DIR=$1
SUT_DIR=$2

for f in $(ls $BUILD_DIR); do
    echo $f syzwrap -d ${SUT_DIR:-$BUILD_DIR} -n $f
done
