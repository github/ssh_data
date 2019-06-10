#!/bin/bash

ssh-keygen -trsa -N "passw0rd" -f ./encrypted_rsa

ssh-keygen -trsa -N "" -f ./rsa_ca
ssh-keygen -tdsa -N "" -f ./dsa_ca
ssh-keygen -tecdsa -N "" -f ./ecdsa_ca
ssh-keygen -ted25519 -N "" -f ./ed25519_ca

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_rsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_rsa_ca_sha2_256
ssh-keygen -trsa-sha2-256 -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_rsa_ca_sha2_256.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_rsa_ca_sha2_512
ssh-keygen -trsa-sha2-512 -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_rsa_ca_sha2_512.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_dsa_ca
ssh-keygen -s dsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_dsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_ecdsa_ca
ssh-keygen -s ecdsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_ecdsa_ca.pub

ssh-keygen -trsa -N "" -f ./rsa_leaf_for_ed25519_ca
ssh-keygen -s ed25519_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding rsa_leaf_for_ed25519_ca.pub

ssh-keygen -tdsa -N "" -f ./dsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding dsa_leaf_for_rsa_ca.pub

ssh-keygen -tecdsa -N "" -f ./ecdsa_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding ecdsa_leaf_for_rsa_ca.pub

ssh-keygen -ted25519 -N "" -f ./ed25519_leaf_for_rsa_ca
ssh-keygen -s rsa_ca -z 123 -n p1,p2 -O clear -I my-ident -O critical:foo=bar -O extension:baz=qwer -O permit-X11-forwarding ed25519_leaf_for_rsa_ca.pub

# pem encoded keys
openssl genrsa -out rsa.plaintext.pem 2048
openssl rsa -aes-128-cbc -passout pass:mypass -in rsa.plaintext.pem -out rsa.encrypted.pem
openssl dsaparam -noout -out dsa.plaintext.pem -genkey 1024
openssl dsa -aes-128-cbc -passout pass:mypass -in dsa.plaintext.pem -out dsa.encrypted.pem
openssl ecparam -noout -out ecdsa.plaintext.pem -name prime256v1 -genkey
openssl ec -aes-128-cbc -passout pass:mypass -in ecdsa.plaintext.pem -out ecdsa.encrypted.pem
chmod 400 *.pem

# Create a certificate with a bad signature. We use ed25519 because the
# signature doesn't have any fancy encoding (Eg. RSA has PKCS1v1.5 and DSA/ECDSA
# have ASN.1).
ruby <<RUBY
require "base64"

encoded = File.read("rsa_leaf_for_ed25519_ca-cert.pub")
algo, b64, comment = encoded.split(" ", 3)
raw = Base64.decode64(b64)

# we flip bits in the last byte, since that's where the signature is.
raw[-1] = (raw[-1].ord ^ 0xff).chr

b64 = Base64.strict_encode64(raw)
encoded = [algo, b64, comment].join(" ")

File.open("bad_signature-cert.pub", "w") { |f| f.write(encoded) }
RUBY
