#!/bin/bash
#
# Script Name: test.sh
# Description: This is testing script
# Author: Oleksandr Turytsia
# Date: October 25, 2023
# Usage: ./test.sh
TEST_PATH="./tests"

make

for file in "$TEST_PATH"/*.in; do
    file_name=$(basename "$file" .in)

    args=$(cat ./$TEST_PATH/$file_name.in)

    out=$(./dns $args 2>&1)
        
    if diff -u ./$TEST_PATH/$file_name.out <(echo "$out"); then
        echo "Test Passed: Output $file_name.in matches the expected result."
    else
        echo "Test Failed: Output does not match the expected result."
    fi
done

make clean
