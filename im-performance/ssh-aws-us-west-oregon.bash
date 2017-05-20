#!/usr/bin/env bash

echo 'Remember to allow inbound traffic from _this_ IP'
echo ""

ssh -i ./aws_us_west_oregon $1
