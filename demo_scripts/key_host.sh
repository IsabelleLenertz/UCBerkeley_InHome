#!/bin/bash

# 1: Host IP
# 2: Gateway IP
# 3: SPI
# 4: Key Data

if [ $# -ge 4 ];
then
	echo "using configured key"
	key=$4
else
	echo "generating key"
	key=$(openssl rand -hex 32)
fi

fromspi=$3
tospi=$( expr $fromspi + 1 )
pvt=192.168.0.0/16

echo "Registering host: $1 with gateway $2"

cmdstr="ip xfrm state add src $1 dst $2 spi $fromspi proto ah auth-trunc hmac (sha256) 0x$key 256 mode tunnel replay-window 32 flag align4 sel src $1/32 dst $pvt"
echo $cmdstr
$($cmdstr)

cmdstr="ip xfrm policy add src $1/32 dst $pvt dir out tmpl src $1 dst $2 proto ah spi $fromspi mode tunnel"
echo $cmdstr
$($cmdstr)

cmdstr="ip xfrm policy add src $pvt dst $1/32 dir fwd tmpl src $2 dst $1 proto ah mode tunnel"
echo $cmdstr
$($cmdstr)
