#!/bin/bash
function smurf ( )
{
    local victim_ip=$1
    local broadcast_ip=$2
    
}

smurf $* & sleep 10; kill $!