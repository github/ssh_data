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
    local key=$filedir/$alg-$keysize-no-options-individual.key

    if [ ! -f "$key" ]; then
        ssh-keygen -q -N "" -t $alg -b $keysize -C "" -f $key
    fi

    cat $message | ssh-keygen -Y sign -n file -f $key > $message.$alg-$keysize-no-options-individual.sig
}

create_key_and_sign_ca() {
    local ca_alg=$1
    local ca_keysize=$2
    local ca_key=$filedir/$ca_alg-$ca_keysize-ca-no-options-certificate.key
    local leaf_alg=$3
    local leaf_keysize=$4
    local keypair=$ca_alg-$ca_keysize-$leaf_alg-$leaf_keysize
    local leaf_key=$filedir/$keypair-leaf-no-options-certificate.key

    if [ ! -f "$ca_key" ]; then
        # Create root
        ssh-keygen -q -N "" -t $ca_alg -b $ca_keysize -C "" -f $ca_key
    fi

    if [ ! -f "$leaf_key" ]; then
        # Create leaf
        ssh-keygen -q -N "" -t $leaf_alg -b $leaf_keysize -C "" -f $leaf_key
        # Sign the leaf with the root.
        ssh-keygen -s $ca_key -O clear -I octocat@example.com $leaf_key.pub
    fi

    cat $message | ssh-keygen -Y sign -n file -f $leaf_key-cert.pub > $message.$keypair-leaf-no-options-certificate.sig
}

create_key_and_sign_options() {
    local alg=$1
    local keysize=$2
    local options=$3
    local key=$filedir/$alg-$keysize-$options-individual.key

    if [ ! -f "$key" ]; then
        ssh-keygen -q -O $options -N "" -t $alg -b $keysize -C "" -f $key
    fi

    cat $message | ssh-keygen -Y sign -n file -f $key > $message.$alg-$keysize-$options-individual.sig
}

create_key_and_sign "rsa" 2048
create_key_and_sign "ecdsa" 256
create_key_and_sign "ecdsa" 384
create_key_and_sign "ecdsa" 521
create_key_and_sign "ed25519" 256
create_key_and_sign_ca "rsa" 2048 "ecdsa" 256
create_key_and_sign_ca "ecdsa" 256 "rsa" 2048

generate_security_keys=0
read -p "Generate security key-backed keys (Requires key and user interaction)? [yN] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    create_key_and_sign "ed25519-sk" 256
    create_key_and_sign "ecdsa-sk" 256

    create_key_and_sign_ca "ecdsa-sk" 256 "rsa" 2048
    create_key_and_sign_ca "ed25519-sk" 256 "rsa" 2048
    create_key_and_sign_ca "rsa" 2048 "ecdsa-sk" 2048
    create_key_and_sign_ca "rsa" 2048 "ed25519-sk" 2048

    create_key_and_sign_ca "ecdsa-sk" 256 "ed25519-sk" 256
    create_key_and_sign_ca "ed25519-sk" 256 "ecdsa-sk" 256

    create_key_and_sign_options "ed25519-sk" 256 "no-touch-required"
    create_key_and_sign_options "ecdsa-sk" 256 "no-touch-required"

    create_key_and_sign_options "ed25519-sk" 256 "verify-required"
    create_key_and_sign_options "ecdsa-sk" 256 "verify-required"
fi

popd
