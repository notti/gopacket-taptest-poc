#!/bin/bash

set -ex

pushd ../../
mkdir google
pushd google
git clone --single-branch -b fix_pfring https://github.com/notti/gopacket.git
popd
popd
