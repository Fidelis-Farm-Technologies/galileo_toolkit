#!/bin/bash
VERSION=`git branch --show-current`

docker push fidelismachine/galileo_toolkit:${VERSION} 
docker push fidelismachine/galileo_toolkit:latest 
