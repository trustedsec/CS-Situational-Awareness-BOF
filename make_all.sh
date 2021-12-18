#!/bin/bash

cd src/SA
ls | while read dir; do
    if [[ -d $dir ]]; then
        cd $dir
        if [[ -f "Makefile" ]]; then
            make >/dev/null
            echo "- $dir"
        fi
        cd ..
    fi
done
cd ../..

