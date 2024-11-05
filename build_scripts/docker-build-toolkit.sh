#!/bin/bash

docker image prune -f
# docker build --no-cache -t gnat_toolkit -f Dockerfile.toolkit .
docker build -t gnat_toolkit -f Dockerfile.toolkit .
