#!/bin/bash

if [[ -z "$1" || -z "$2" || -z "$3" ]]; then
	echo "Usage: $0 [secret] [filepath] [time]"
	echo "Time is the URL validity time in seconds."
	exit 1
fi

date=`date +%s`

secret="$1"
url="$2"
expire=$(($date + $3))

echo " -> Expires in $3 secs, $date -> $expire."

hextime=$(printf "%x" $expire)

echo " -> Expiry time is $hextime."

string="$url/$secret/$hextime"

echo " -> Hash string is $string"

hash=$(echo -n "${string}" | md5sum | cut '-d ' -f1)

echo " -> Hash is $hash"

echo "The full protected file path is: $url/$hash/$hextime" 
