#!/bin/bash

ssh-keygen -trsa -b2048 -N "" -f ./rsa_ca
ssh-keygen -trsa -b2048 -N "" -f ./rsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -I key-id-rsa-leaf-for-rsa-ca rsa_leaf_for_rsa_ca.pub
