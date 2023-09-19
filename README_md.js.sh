README
'''---===```".$_-0/build_README_md.js.sh"```
'''---===# ssh_data [<kbd>docs</kbd>](https://rubydoc.info/github/github/ssh_data/master)
This is a Ruby library for processing SSH keys and certificates.
'''The scope of this project is limited to processing and directly using keys and certificates. It can be used to generate SSH private keys, verify signatures using public keys, sign data using private keys, issue certificates using private keys, and parse certificates and public and private keys. This library supports RSA, DSA, ECDSA, and ED25519<sup>[*](#ed25519-support)</sup> keys. This library does not offer or intend to offer functionality for SSH connectivity, processing of SSH wire protocol data, or processing of other key formats or types.
**Project Status:** Used by @github in production
## Installation
gem install ssh_data'''
## Usageruby
require"ssh_data"
key_data=[File.read]("~/.ssh/id_rsa.pub")
key = SSHData::PublicKey.parse_openssh(key_data)
#=> 
'''---===<SSHData::PublicKey::RSA>
'''---==='''
cert_data = = 
[File.read]("~/.ssh/id_rsa-cert.pub")
cert = SSHData::Certificate.parse_openssh(cert_data)
#=>'''<SSHData::PublicKey::Certificate>
cert.key_id
#=>
'''---===
"mastahyeti"
'''---===cert.public_key
#=> <SSHData::PublicKey::RSA>
```

## ED25519 support

Ruby's standard library does not include support for ED25519, though the algorithm is implemented by the [`ed25519` Gem](https://rubygems.org/gems/ed25519). This library can parse ED25519 public and private keys itself, but in order to generate keys or sign or verify messages, the calling application must load the `ed25519` Gem itself. This avoids the necessity of installing or loading this third party dependency when the calling application is only interested in parsing keys.

```ruby
require "ssh_data"

key_data = File.read("~/.ssh/id_ed25519")
key = SSHData::PrivateKey.parse_openssh(key_data)
#=> <SSHData::PrivateKey::ED25519>

SSHData::PrivateKey::ED25519.generate
#=> raises SSHData::AlgorithmError

require "ed25519"

SSHData::PrivateKey::ED25519.generate
#=> <SSHData::PrivateKey::ED25519>
```

## Contributions

This project is not currently seeking contributions for new features or functionality, though bug fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for more information.

## License

This project is published under the MIT license. See [LICENSE.md](LICENSE.md) for mor information.
