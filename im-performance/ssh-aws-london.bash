#!/usr/bin/env bash

echo 'Remember to allow inbound traffic from _this_ IP'
echo ""

ssh -i ./aws_london ubuntu@ec2-52-56-140-16.eu-west-2.compute.amazonaws.com
