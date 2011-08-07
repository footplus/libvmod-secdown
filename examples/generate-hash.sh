#!/bin/bash

if [[ -z "$1" || -z "$2" || -z "$3" ]]; then
	echo "Usage: $0 {secret} {filepath} {time} [max-hash-length]"
	echo "Time is the URL validity time in seconds."
	exit 1
fi

date=`date +%s`

secret="$1"
url="$2"
expire=$(($date + $3))
length=$4

echo " -> Expires in $3 secs, $date -> $expire."

hextime=$(printf "%x" $expire)

if [ ! -z "$length" ]; then
	hexlen="x$(printf "%04.4x" $length)"
	echo " -> Prefix len is $length (0$hexlen)"
	url="$(echo $url | cut -b 1-$length)"
	echo " -> Shortening URL: $url"
else
	hexlen=""
fi

echo " -> Expiry time is $hextime."

string="$url/$secret/$hextime$hexlen"

echo " -> Hash string is $string"

hash=$(echo -n "${string}" | md5sum | cut '-d ' -f1)

echo " -> Hash is $hash"

echo "The full protected file path is: $url/$hash/$hextime$hexlen" 
