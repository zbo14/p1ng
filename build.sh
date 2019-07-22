#!/bin/bash -e

cd "$(dirname $0)"

mkdir -p bin

gcc -Wall -o bin/p1ng src/*