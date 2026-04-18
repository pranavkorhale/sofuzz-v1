#!/bin/sh

wget https://zenodo.org/records/15700199/files/target_APK.tar.gz
tar xvf target_APK.tar.gz
docker build . -t sofuzz
