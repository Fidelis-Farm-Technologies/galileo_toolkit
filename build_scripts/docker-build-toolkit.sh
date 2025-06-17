#!/bin/bash
VERSION=`git branch --show-current`

#docker build --no-cache -t fidelismachine/galileo_toolkit:${VERSION} -t fidelismachine/galileo_toolkit:latest -f Dockerfile .
docker build -t fidelismachine/galileo_toolkit:${VERSION} -t fidelismachine/galileo_toolkit:latest -f Dockerfile .
