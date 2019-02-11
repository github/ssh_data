# ssh_data

This is a Ruby library for parsing SSH public keys and certificates.

## Installation

```
gem install ssh_data
```

## Usage

```ruby
require "ssh_data"

key_data = File.read("~/.ssh/id_rsa.pub")
key = SSHData::PublicKey.parse_openssh(key_data)
#=> <SSHData::PublicKey::RSA>

cert_data = = File.read("~/.ssh/id_rsa-cert.pub")
cert = SSHData::Certificate.parse_openssh(cert_data)
#=> <SSHData::PublicKey::Certificate>

cert.key_id
#=> "mastahyeti"

cert.public_key
#=> <SSHData::PublicKey::RSA>
```
