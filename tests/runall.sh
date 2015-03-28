#!/bin/bash

for test in test_*; do
    cd ${test}
    ./run.sh
    cd ..
done
