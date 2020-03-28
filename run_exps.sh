#!/bin/bash

limit=0
for i in {1..49} ; do
    echo "${i}";
    timeout 20m python3 main.py --binary_idx=${i} &
    let limit=limit+1;
    if (( limit == 5 )); then
        echo "wating";
        wait;
        let limit=0;
    fi;
done;

wait