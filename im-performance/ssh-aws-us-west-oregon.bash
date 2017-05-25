#!/usr/bin/env bash

echo 'Remember to allow inbound traffic from _this_ IP'
echo ""

ssh -i ./aws_us_west_oregon ubuntu@ec2-52-36-141-199.us-west-2.compute.amazonaws.com
