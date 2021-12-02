#!/usr/bin/env bash

filedir=`dirname $0`
pushd $filedir

message=$filedir/message

if [ ! -f "$message" ]; then
    dd if=/dev/urandom count=1 bs=64 | base64 > $message
fi

create_key_and_sign() {
    local alg=$1
    local keysize=$2
    local key=$filedir/$alg-$keysize.key
    yes | ssh-keygen -q -N "" -t $alg -b $keysize -C "" -f $key
    cat $message | ssh-keygen -Y sign -n file -f $key > $message.$alg-$keysize.sig
}

create_key_and_sign "rsa" 2048
create_key_and_sign "ecdsa" 256
create_key_and_sign "ecdsa" 384
create_key_and_sign "ecdsa" 521
create_key_and_sign "ed25519" 256

generate_security_keys=0
read -p "Generate security key-backed keys (Requires key and user interaction)? [yN] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    create_key_and_sign "ed25519-sk" 256
    create_key_and_sign "ecdsa-sk" 256
fi

popd
