#!/bin/bash

LABEL_DEVEL="development"

# Rebuild image
docker build --tag eapol_tester:latest .

# Start container with new image in interactive shell
docker run --label $LABEL_DEVEL -ti eapol_tester 

# Delete all freeradius-1x containers with the "development" tag
docker ps -q -a -f label=$LABEL_DEVEL | xargs docker rm
