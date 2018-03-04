#!/bin/bash

LABEL_DEVEL="development"

# Rebuild image
docker build --tag netgab/eapol_tester:0.1-ubuntu ..

# Start container with new image in interactive shell
docker run --label $LABEL_DEVEL -ti netgab/eapol_tester:0.1-ubuntu

# Delete all freeradius-1x containers with the "development" tag
docker ps -q -a -f label=$LABEL_DEVEL | xargs docker rm
