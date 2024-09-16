#!/bin/bash

# docker build --no-cache -t gnat_apps -f Dockerfile.toolkit .
docker build -t gnat_toolkit -f Dockerfile.toolkit .

