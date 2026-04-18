#!/bin/sh
docker run -w /mnt -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd):/mnt --rm --name=sofuzz-container --privileged -it sofuzz /bin/bash

