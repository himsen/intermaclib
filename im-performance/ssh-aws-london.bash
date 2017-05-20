#!/usr/bin/env bash

echo 'Remember to allow inbound traffic from _this_ IP'
echo ""

ssh -i ./aws_london $1
