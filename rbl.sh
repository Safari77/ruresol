#!/bin/bash

RBLRC=rblcheckrc

if [[ -z "$1" ]]; then
    echo missing parameter
    exit 1
fi

IP4=$1
IFS='.' read -r -a octets <<< "$IP4"
if [[ "${#octets[@]}" -ne 4 ]]; then
    echo invalid IPv4 address
    exit 1
fi

for octet in "${octets[@]}"; do
    if ! [[ "$octet" =~ ^[0-9]+$ ]]; then
        echo error: octet \""$octet"\" contains non-numeric characters
        exit 1
    fi
    if (( 10#$octet < 0 || 10#$octet > 255 )); then
        echo error: octet \""$octet"\" out of range
        exit 1
    fi
done
REVIP4="${octets[3]}.${octets[2]}.${octets[1]}.${octets[0]}"

if [[ ! -f "$RBLRC" ]]; then
    echo file \""$RBLRC"\" does not exist
    exit 1
fi
while read -r key rest; do
    if [[ "$key" == "-s" ]]; then
        echo "$REVIP4"."${rest}"
    fi
done < "$RBLRC" | ruresol -a
