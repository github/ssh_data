#!/bin/bash

ssh-keygen -trsa -N "" -f ./rsa_ca
ssh-keygen -tdsa -N "" -f ./dsa_ca
ssh-keygen -tecdsa -N "" -f ./ecdsa_ca
ssh-keygen -ted25519 -N "" -f ./ed25519_ca

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear rsa_leaf_for_rsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_dsa_ca
ssh-keygen -s dsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear rsa_leaf_for_dsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_ecdsa_ca
ssh-keygen -s ecdsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear rsa_leaf_for_ecdsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_ed25519_ca
ssh-keygen -s ed25519_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear rsa_leaf_for_ed25519_ca.pub

ssh-keygen -tdsa -N "" -f ./dsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear dsa_leaf_for_rsa_ca.pub

ssh-keygen -tecdsa -N "" -f ./ecdsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear ecdsa_leaf_for_rsa_ca.pub

ssh-keygen -ted25519 -N "" -f ./ed25519_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n my-principal -I my-ident -O critical:foo=bar -O extension:baz=qwer -O clear ed25519_leaf_for_rsa_ca.pub

