#!/bin/sh

set -ex

go build -o test main.go
sudo ./test
