require "securerandom"
require_relative "./spec_helper"

describe SSHData::Encoding do
  let(:junk) { String.new("\xff\xff", encoding: Encoding::ASCII_8BIT) }

  describe "#pem_type" do
    let(:type) { "FOO BAR" }
    let(:head) { "-----BEGIN #{type}-----" }
    let(:foot) { "-----END #{type}-----" }
    let(:data) { "foobarbaz" }
    let(:b64)  { Base64.strict_encode64(data) }
    let(:sep)  { "\n" }
    let(:pem)  { [head, b64, foot].join(sep) }

    it "works" do
      expect(described_class.pem_type(pem)).to eq(type)
    end

    describe "carriage returns" do
      let(:sep) { "\r\n" }

      it "works" do
        expect(described_class.pem_type(pem)).to eq(type)
      end
    end

    describe "bad header" do
      let(:head) { "----BEGIN #{type}-----" }

      it "blows up" do
        expect{ described_class.pem_type(pem) }.to raise_error(SSHData::DecodeError)
      end
    end
  end

  describe "#decode_pem" do
    let(:type) { "FOO BAR" }
    let(:head) { "-----BEGIN #{type}-----" }
    let(:foot) { "-----END #{type}-----" }
    let(:data) { "foobarbaz" }
    let(:b64)  { Base64.strict_encode64(data) }
    let(:sep)  { "\n" }
    let(:pem)  { [head, b64, foot].join(sep) }

    it "works" do
      expect(described_class.decode_pem(pem, type)).to eq(data)
    end

    describe "carriage returns" do
      let(:sep) { "\r\n" }

      it "works" do
        expect(described_class.decode_pem(pem, type)).to eq(data)
      end
    end

    describe "bad header" do
      let(:head) { "----BEGIN #{type}-----" }

      it "blows up" do
        expect{ described_class.decode_pem(pem, type) }.to raise_error(SSHData::DecodeError)
      end
    end

    describe "bad header type" do
      let(:head) { "-----BEGIN SOMETHING ELSE-----" }

      it "blows up" do
        expect{ described_class.decode_pem(pem, type) }.to raise_error(SSHData::DecodeError)
      end
    end

    describe "bad footer" do
      let(:foot) { "-----END #{type}----" }

      it "blows up" do
        expect{ described_class.decode_pem(pem, type) }.to raise_error(SSHData::DecodeError)
      end
    end

    describe "bad footer type" do
      let(:foot) { "-----END SOMETHING ELSE-----" }

      it "blows up" do
        expect{ described_class.decode_pem(pem, type) }.to raise_error(SSHData::DecodeError)
      end
    end

    describe "bad b64" do
      let(:b64)  { "foo" }

      it "blows up" do
        expect{ described_class.decode_pem(pem, type) }.to raise_error(SSHData::DecodeError)
      end
    end
  end

  describe "#decode_openssh_private_key" do
    let(:rsa_data)     { described_class.decode_openssh_private_key(fixture("rsa_leaf_for_rsa_ca",     binary: true, pem: true)).first }
    let(:dsa_data)     { described_class.decode_openssh_private_key(fixture("dsa_leaf_for_rsa_ca",     binary: true, pem: true)).first }
    let(:ecdsa_data)   { described_class.decode_openssh_private_key(fixture("ecdsa_leaf_for_rsa_ca",   binary: true, pem: true)).first }
    let(:ed25519_data) { described_class.decode_openssh_private_key(fixture("ed25519_leaf_for_rsa_ca", binary: true, pem: true)).first }

    it "can decode rsa" do
      expect { rsa_data }.not_to raise_error
      expect(rsa_data[:ciphername]).to eq("none")
      expect(rsa_data[:kdfname]).to eq("none")
      expect(rsa_data[:kdfoptions]).to eq("")
      expect(rsa_data[:nkeys]).to eq(1)

      expect(rsa_data[:public_keys]).to be_a(Array)
      expect(rsa_data[:public_keys].length).to eq(1)
      expect {
        SSHData::PublicKey.parse_rfc4253(rsa_data[:public_keys].first)
      }.not_to raise_error

      expect(rsa_data[:checkint1]).to be_a(Integer)
      expect(rsa_data[:checkint2]).to be_a(Integer)
      expect(rsa_data[:checkint1]).to eq(rsa_data[:checkint2])

      expect(rsa_data[:private_keys]).to be_a(Array)
      expect(rsa_data[:private_keys].length).to eq(1)

      expect(rsa_data[:padding]).to eq("\x01\x02\x03\x04")
    end

    it "can decode dsa" do
      expect { dsa_data }.not_to raise_error
      expect(dsa_data[:ciphername]).to eq("none")
      expect(dsa_data[:kdfname]).to eq("none")
      expect(dsa_data[:kdfoptions]).to eq("")
      expect(dsa_data[:nkeys]).to eq(1)

      expect(dsa_data[:public_keys]).to be_a(Array)
      expect(dsa_data[:public_keys].length).to eq(1)
      expect {
        SSHData::PublicKey.parse_rfc4253(dsa_data[:public_keys].first)
      }.not_to raise_error

      expect(dsa_data[:checkint1]).to be_a(Integer)
      expect(dsa_data[:checkint2]).to be_a(Integer)
      expect(dsa_data[:checkint1]).to eq(dsa_data[:checkint2])

      expect(dsa_data[:private_keys]).to be_a(Array)
      expect(dsa_data[:private_keys].length).to eq(1)

      expect(dsa_data[:padding]).to eq("\x01\x02\x03\x04")
    end

    it "can decode ecdsa" do
      expect { ecdsa_data }.not_to raise_error
      expect(ecdsa_data[:ciphername]).to eq("none")
      expect(ecdsa_data[:kdfname]).to eq("none")
      expect(ecdsa_data[:kdfoptions]).to eq("")
      expect(ecdsa_data[:nkeys]).to eq(1)

      expect(ecdsa_data[:public_keys]).to be_a(Array)
      expect(ecdsa_data[:public_keys].length).to eq(1)
      expect {
        SSHData::PublicKey.parse_rfc4253(ecdsa_data[:public_keys].first)
      }.not_to raise_error

      expect(ecdsa_data[:checkint1]).to be_a(Integer)
      expect(ecdsa_data[:checkint2]).to be_a(Integer)
      expect(ecdsa_data[:checkint1]).to eq(ecdsa_data[:checkint2])

      expect(ecdsa_data[:private_keys]).to be_a(Array)
      expect(ecdsa_data[:private_keys].length).to eq(1)

      expect(ecdsa_data[:padding]).to eq("\x01")
    end

    it "can decode ed25519" do
      expect { ed25519_data }.not_to raise_error
      expect(ed25519_data[:ciphername]).to eq("none")
      expect(ed25519_data[:kdfname]).to eq("none")
      expect(ed25519_data[:kdfoptions]).to eq("")
      expect(ed25519_data[:nkeys]).to eq(1)

      expect(ed25519_data[:public_keys]).to be_a(Array)
      expect(ed25519_data[:public_keys].length).to eq(1)
      expect {
        SSHData::PublicKey.parse_rfc4253(ed25519_data[:public_keys].first)
      }.not_to raise_error

      expect(ed25519_data[:checkint1]).to be_a(Integer)
      expect(ed25519_data[:checkint2]).to be_a(Integer)
      expect(ed25519_data[:checkint1]).to eq(ed25519_data[:checkint2])

      expect(ed25519_data[:private_keys]).to be_a(Array)
      expect(ed25519_data[:private_keys].length).to eq(1)

      expect(ed25519_data[:padding]).to eq("\x01\x02\x03\x04\x05\x06\07")
    end

    it "raises on bad magic bytes" do
      raw = fixture("rsa_leaf_for_rsa_ca", binary: true, pem: true)

      # magic bytes come first
      offset = 0

      raw[offset] = (raw[offset].ord ^ 0xff).chr

      expect {
        described_class.decode_openssh_private_key(raw)
      }.to raise_error(SSHData::DecodeError)
    end

    it "raises on unsupported encryption algos" do
      raw = fixture("rsa_leaf_for_rsa_ca", binary: true, pem: true)

      # ciphername comes right after TLV after magic bytes
      offset = described_class::OPENSSH_PRIVATE_KEY_MAGIC.bytesize + 4

      raw[offset] = (raw[offset].ord ^ 0xff).chr

      expect {
        described_class.decode_openssh_private_key(raw)
      }.to raise_error(SSHData::DecryptError)
    end

    it "raises on unsupported kdf algos" do
      raw = fixture("rsa_leaf_for_rsa_ca", binary: true, pem: true)

      # ciphername comes right after TLV after magic bytes
      offset = described_class::OPENSSH_PRIVATE_KEY_MAGIC.bytesize + 4

      # kdfname comes right after TLV of ciphername "none"
      offset += 8

      raw[offset] = (raw[offset].ord ^ 0xff).chr

      expect {
        described_class.decode_openssh_private_key(raw)
      }.to raise_error(SSHData::DecryptError)
    end

    it "raises on bad checkint" do
      raw = fixture("rsa_leaf_for_rsa_ca", binary: true, pem: true)

      check = [rsa_data[:checkint1]].pack("L>")

      raw2 = raw.sub(check, "asdf")

      expect(raw).not_to eq(raw2)

      expect {
        described_class.decode_openssh_private_key(raw2)
      }.to raise_error(SSHData::DecryptError)
    end

    it "raises on bad padding" do
      raw = fixture("rsa_leaf_for_rsa_ca", binary: true, pem: true)
      raw[-1] = (raw[-1].ord ^ 0xff).chr

      expect {
        described_class.decode_openssh_private_key(raw)
      }.to raise_error(SSHData::DecodeError)
    end
  end

  describe("#decode_public_key") do
    let(:rsa_data)     { described_class.decode_public_key(fixture("rsa_leaf_for_rsa_ca.pub",     binary: true)).first }
    let(:dsa_data)     { described_class.decode_public_key(fixture("dsa_leaf_for_rsa_ca.pub",     binary: true)).first }
    let(:ecdsa_data)   { described_class.decode_public_key(fixture("ecdsa_leaf_for_rsa_ca.pub",   binary: true)).first }
    let(:ed25519_data) { described_class.decode_public_key(fixture("ed25519_leaf_for_rsa_ca.pub", binary: true)).first }

    it "raises on unknown public key algorithms" do
      raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)

      # first four bytes are lenth for algo field. flip bits in first byte of algo
      raw[5] = (raw[5].ord ^ 0xff).chr

      expect {
        described_class.decode_public_key(raw)
      }.to raise_error(SSHData::AlgorithmError)
    end

    it "can decode a public key at an offset" do
      prefix = "foobar"
      raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)
      with_prefix = [prefix, raw].join

      data, _ = described_class.decode_public_key(with_prefix, prefix.bytesize, nil).first

      expect(data).to eq(rsa_data)
    end

    it "can skip the algo when decoding a public key" do
      raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)
      algo, offset = described_class.decode_string(raw)
      data, _ = described_class.decode_public_key(raw, offset, algo)

      expect(data).to eq(rsa_data)
    end

    it "can decode an RSA public key" do
      expect(rsa_data[:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(rsa_data[:e]).to be_a(OpenSSL::BN)
      expect(rsa_data[:n]).to be_a(OpenSSL::BN)
    end

    it "can decode an DSA public key" do
      expect(dsa_data[:algo]).to eq(SSHData::PublicKey::ALGO_DSA)
      expect(dsa_data[:p]).to be_a(OpenSSL::BN)
      expect(dsa_data[:q]).to be_a(OpenSSL::BN)
      expect(dsa_data[:g]).to be_a(OpenSSL::BN)
      expect(dsa_data[:y]).to be_a(OpenSSL::BN)
    end

    it "can decode an ECDSA public key" do
      expect(ecdsa_data[:algo]).to eq(SSHData::PublicKey::ALGO_ECDSA256)
      expect(ecdsa_data[:curve]).to eq("nistp256")
      expect(ecdsa_data[:public_key]).to be_a(String)
    end

    it "can decode an ED25519 public key" do
      expect(ed25519_data[:algo]).to eq(SSHData::PublicKey::ALGO_ED25519)
      expect(ed25519_data[:pk]).to be_a(String)
    end
  end

  describe("#decode_string_public_key") do
    let(:string_public_key) { described_class.encode_string(fixture("rsa_leaf_for_rsa_ca.pub", binary: true)) }
    let(:public_key)        { described_class.decode_public_key(fixture("rsa_leaf_for_rsa_ca.pub", binary: true)).first }

    subject { described_class.decode_string_public_key(string_public_key).first }

    it "matches normal decoding" do
      expect(subject).to eq(public_key)
    end
  end

  describe("#decode_certificate") do
    let(:rsa_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
    let(:dsa_data)     { described_class.decode_certificate(fixture("dsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
    let(:ecdsa_data)   { described_class.decode_certificate(fixture("ecdsa_leaf_for_rsa_ca-cert.pub",   binary: true)).first }
    let(:ed25519_data) { described_class.decode_certificate(fixture("ed25519_leaf_for_rsa_ca-cert.pub", binary: true)).first }

    let(:rsa_ca_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
    let(:dsa_ca_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_dsa_ca-cert.pub",     binary: true)).first }
    let(:ecdsa_ca_data)   { described_class.decode_certificate(fixture("rsa_leaf_for_ecdsa_ca-cert.pub",   binary: true)).first }
    let(:ed25519_ca_data) { described_class.decode_certificate(fixture("rsa_leaf_for_ed25519_ca-cert.pub", binary: true)).first }

    it "raises on unknown certificate algorithms" do
      raw = fixture("rsa_leaf_for_rsa_ca-cert.pub", binary: true)

      # first four bytes are lenth for algo field. flip bits in first byte of algo
      raw[5] = (raw[5].ord ^ 0xff).chr

      expect {
        described_class.decode_certificate(raw)
      }.to raise_error(SSHData::AlgorithmError)
    end

    it "can decode a certificate at an offset" do
      prefix = "foobar"
      raw = fixture("rsa_leaf_for_rsa_ca-cert.pub", binary: true)
      with_prefix = [prefix, raw].join

      data = described_class.decode_certificate(with_prefix, prefix.bytesize).first

      expect(data).to eq(rsa_data)
    end

    it "can decode RSA certificates" do
      expect(rsa_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(rsa_data[:nonce]).to be_a(String)
      expect(rsa_data[:nonce].length).to eq(32)

      expect(rsa_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(rsa_data[:public_key][:e]).to be_a(OpenSSL::BN)
      expect(rsa_data[:public_key][:n]).to be_a(OpenSSL::BN)

      expect(rsa_data[:serial]).to eq(123)
      expect(rsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(rsa_data[:key_id]).to eq("my-ident")
      expect(rsa_data[:valid_principals]).to eq(["p1", "p2"])
      expect(rsa_data[:valid_after]).to eq(Time.at(0))
      expect(rsa_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(rsa_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(rsa_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(rsa_data[:reserved]).to eq("")

      expect(rsa_data[:signature_key]).to be_a(Hash)

      expect(rsa_data[:signature]).to be_a(String)
      expect(rsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode DSA certificates" do
      expect(dsa_data[:algo]).to eq(SSHData::Certificate::ALGO_DSA)

      expect(dsa_data[:nonce]).to be_a(String)
      expect(dsa_data[:nonce].length).to eq(32)

      expect(dsa_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_DSA)
      expect(dsa_data[:public_key][:p]).to be_a(OpenSSL::BN)
      expect(dsa_data[:public_key][:q]).to be_a(OpenSSL::BN)
      expect(dsa_data[:public_key][:g]).to be_a(OpenSSL::BN)
      expect(dsa_data[:public_key][:y]).to be_a(OpenSSL::BN)

      expect(dsa_data[:serial]).to eq(123)
      expect(dsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(dsa_data[:key_id]).to eq("my-ident")
      expect(dsa_data[:valid_principals]).to eq(["p1", "p2"])
      expect(dsa_data[:valid_after]).to eq(Time.at(0))
      expect(dsa_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(dsa_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(dsa_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(dsa_data[:reserved]).to eq("")

      expect(dsa_data[:signature_key]).to be_a(Hash)

      expect(dsa_data[:signature]).to be_a(String)
      expect(dsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode ECDSA certificates" do
      expect(ecdsa_data[:algo]).to eq(SSHData::Certificate::ALGO_ECDSA256)

      expect(ecdsa_data[:nonce]).to be_a(String)
      expect(ecdsa_data[:nonce].length).to eq(32)

      expect(ecdsa_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_ECDSA256)
      expect(ecdsa_data[:public_key][:curve]).to eq("nistp256")
      expect(ecdsa_data[:public_key][:public_key]).to be_a(String)

      expect(ecdsa_data[:serial]).to eq(123)
      expect(ecdsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ecdsa_data[:key_id]).to eq("my-ident")
      expect(ecdsa_data[:valid_principals]).to eq(["p1", "p2"])
      expect(ecdsa_data[:valid_after]).to eq(Time.at(0))
      expect(ecdsa_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(ecdsa_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(ecdsa_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(ecdsa_data[:reserved]).to eq("")

      expect(ecdsa_data[:signature_key]).to be_a(Hash)

      expect(ecdsa_data[:signature]).to be_a(String)
      expect(ecdsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode ED25519 certificates" do
      expect(ed25519_data[:algo]).to eq(SSHData::Certificate::ALGO_ED25519)

      expect(ed25519_data[:nonce]).to be_a(String)
      expect(ed25519_data[:nonce].length).to eq(32)

      expect(ed25519_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_ED25519)
      expect(ed25519_data[:public_key][:pk]).to be_a(String)

      expect(ed25519_data[:serial]).to eq(123)
      expect(ed25519_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ed25519_data[:key_id]).to eq("my-ident")
      expect(ed25519_data[:valid_principals]).to eq(["p1", "p2"])
      expect(ed25519_data[:valid_after]).to eq(Time.at(0))
      expect(ed25519_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(ed25519_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(ed25519_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(ed25519_data[:reserved]).to eq("")

      expect(ed25519_data[:signature_key]).to be_a(Hash)

      expect(ed25519_data[:signature]).to be_a(String)
      expect(ed25519_data[:signature].bytesize).to eq(271)
    end

    it "can decode certs from RSA CAs" do
      expect(rsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(rsa_ca_data[:nonce]).to be_a(String)
      expect(rsa_ca_data[:nonce].length).to eq(32)

      expect(rsa_ca_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(rsa_ca_data[:public_key][:e]).to be_a(OpenSSL::BN)
      expect(rsa_ca_data[:public_key][:n]).to be_a(OpenSSL::BN)

      expect(rsa_ca_data[:serial]).to eq(123)
      expect(rsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(rsa_ca_data[:key_id]).to eq("my-ident")
      expect(rsa_ca_data[:valid_principals]).to eq(["p1", "p2"])
      expect(rsa_ca_data[:valid_after]).to eq(Time.at(0))
      expect(rsa_ca_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(rsa_ca_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(rsa_ca_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(rsa_ca_data[:reserved]).to eq("")

      expect(rsa_ca_data[:signature_key]).to be_a(Hash)

      expect(rsa_ca_data[:signature]).to be_a(String)
      expect(rsa_ca_data[:signature].bytesize).to eq(271)
    end

    it "can decode certs from DSA CAs" do
      expect(dsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(dsa_ca_data[:nonce]).to be_a(String)
      expect(dsa_ca_data[:nonce].length).to eq(32)

      expect(dsa_ca_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(dsa_ca_data[:public_key][:e]).to be_a(OpenSSL::BN)
      expect(dsa_ca_data[:public_key][:n]).to be_a(OpenSSL::BN)

      expect(dsa_ca_data[:serial]).to eq(123)
      expect(dsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(dsa_ca_data[:key_id]).to eq("my-ident")
      expect(dsa_ca_data[:valid_principals]).to eq(["p1", "p2"])
      expect(dsa_ca_data[:valid_after]).to eq(Time.at(0))
      expect(dsa_ca_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(dsa_ca_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(dsa_ca_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(dsa_ca_data[:reserved]).to eq("")

      expect(dsa_ca_data[:signature_key]).to be_a(Hash)
      expect(dsa_ca_data[:signature]).to be_a(String)
    end

    it "can decode certs from ECDSA CAs" do
      expect(ecdsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(ecdsa_ca_data[:nonce]).to be_a(String)
      expect(ecdsa_ca_data[:nonce].length).to eq(32)

      expect(ecdsa_ca_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(ecdsa_ca_data[:public_key][:e]).to be_a(OpenSSL::BN)
      expect(ecdsa_ca_data[:public_key][:n]).to be_a(OpenSSL::BN)

      expect(ecdsa_ca_data[:serial]).to eq(123)
      expect(ecdsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ecdsa_ca_data[:key_id]).to eq("my-ident")
      expect(ecdsa_ca_data[:valid_principals]).to eq(["p1", "p2"])
      expect(ecdsa_ca_data[:valid_after]).to eq(Time.at(0))
      expect(ecdsa_ca_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(ecdsa_ca_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(ecdsa_ca_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(ecdsa_ca_data[:reserved]).to eq("")

      expect(ecdsa_ca_data[:signature_key]).to be_a(Hash)
      expect(ecdsa_ca_data[:signature]).to be_a(String)
    end

    it "can decode certs from ED25519 CAs" do
      expect(ed25519_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(ed25519_ca_data[:nonce]).to be_a(String)
      expect(ed25519_ca_data[:nonce].length).to eq(32)

      expect(ed25519_ca_data[:public_key][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(ed25519_ca_data[:public_key][:e]).to be_a(OpenSSL::BN)
      expect(ed25519_ca_data[:public_key][:n]).to be_a(OpenSSL::BN)

      expect(ed25519_ca_data[:serial]).to eq(123)
      expect(ed25519_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ed25519_ca_data[:key_id]).to eq("my-ident")
      expect(ed25519_ca_data[:valid_principals]).to eq(["p1", "p2"])
      expect(ed25519_ca_data[:valid_after]).to eq(Time.at(0))
      expect(ed25519_ca_data[:valid_before]).to eq(Time.at((2**64)-1))
      expect(ed25519_ca_data[:critical_options]).to eq({"foo"=>"bar"})
      expect(ed25519_ca_data[:extensions]).to eq({"permit-X11-forwarding"=>true, "baz"=>"qwer"})
      expect(ed25519_ca_data[:reserved]).to eq("")

      expect(ed25519_ca_data[:signature_key]).to be_a(Hash)
      expect(ed25519_ca_data[:signature]).to be_a(String)
    end
  end

  describe("strings") do
    test_cases = []

    test_cases << [
      :normal,                  # name
      "foobar",                 # raw
      "\x00\x00\x00\x06foobar", # encoded
    ]

    test_cases << [
      :empty,             # name
      "",                 # raw
      "\x00\x00\x00\x00", # encoded
    ]

    test_cases.each do |name, raw, encoded|
      describe("#{name} values") do
        it "can decode" do
          raw2, read = described_class.decode_string(encoded + junk)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can at an offset" do
          raw2, read = described_class.decode_string(junk + encoded + junk, junk.bytesize)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can encode" do
          encoded2 = described_class.encode_string(raw)
          expect(encoded2).to eq(encoded)
        end
      end
    end
  end

  describe("lists") do
    test_cases = []

    test_cases << [
      :normal,                                                                       # name
      %w(one two three),                                                             # raw
      "\x00\x00\x00\x17\x00\x00\x00\x03one\x00\x00\x00\x03two\x00\x00\x00\x05three", # encoded
    ]

    test_cases << [
      :empty,             # name
      %w(),               # raw
      "\x00\x00\x00\x00", # encoded
    ]

    test_cases.each do |name, raw, encoded|
      describe("#{name} values") do
        it "can decode" do
          raw2, read = described_class.decode_list(encoded + junk)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can decode at an offset" do
          raw2, read = described_class.decode_list(junk + encoded + junk, junk.bytesize)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can encode" do
          encoded2 = described_class.encode_list(raw)
          expect(encoded2).to eq(encoded)
        end
      end
    end
  end

  describe("mpint") do
    test_cases = []

    test_cases << [
      :positive,                                                                     # name
      OpenSSL::BN.new(0x01020304),                                                   # raw
      String.new("\x00\x00\x00\x04\x01\x02\x03\x04", encoding: Encoding::ASCII_8BIT) # encoded
    ]

    test_cases << [
      :zero,                                                         # name
      OpenSSL::BN.new(0x00),                                         # raw
      String.new("\x00\x00\x00\x00", encoding: Encoding::ASCII_8BIT) # encoded
    ]

    test_cases.each do |name, raw, encoded|
      describe("#{name} values") do
        it "can decode" do
          raw2, read = described_class.decode_mpint(encoded + junk)
          expect(raw2.to_i).to eq(raw.to_i)
          expect(read).to eq(encoded.bytesize)
        end

        it "can decode at an offset" do
          raw2, read = described_class.decode_mpint(junk + encoded + junk, junk.bytesize)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can encode" do
          encoded2 = described_class.encode_mpint(raw)
          expect(encoded2).to eq(encoded)
        end
      end
    end
  end

  describe("time") do
    let(:raw)     { Time.at((rand * 1000000000).to_i) }
    let(:encoded) { [raw.to_i].pack("Q>") }
    let(:junk)    { String.new("\xff\xff", encoding: Encoding::ASCII_8BIT) }

    it "can decode" do
      raw2, read = described_class.decode_time(encoded + junk)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can decode at an offset" do
      raw2, read = described_class.decode_time(junk + encoded + junk, junk.bytesize)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can encode" do
      encoded2 = described_class.encode_time(raw)
      expect(encoded2).to eq(encoded)
    end
  end

  describe("uint64") do
    let(:raw)     { 0x1234567890abcdef }
    let(:encoded) { String.new("\x12\x34\x56\x78\x90\xab\xcd\xef", encoding: Encoding::ASCII_8BIT) }
    let(:junk)    { String.new("\xff\xff", encoding: Encoding::ASCII_8BIT) }

    it "can decode" do
      raw2, read = described_class.decode_uint64(encoded + junk)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can decode at an offset" do
      raw2, read = described_class.decode_uint64(junk + encoded + junk, junk.bytesize)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can encode" do
      encoded2 = described_class.encode_uint64(raw)
      expect(encoded2).to eq(encoded)
    end
  end

  describe("uint32") do
    let(:raw)     { 0x12345678 }
    let(:encoded) { String.new("\x12\x34\x56\x78", encoding: Encoding::ASCII_8BIT) }
    let(:junk)    { String.new("\xff\xff", encoding: Encoding::ASCII_8BIT) }

    it "can decode" do
      raw2, read = described_class.decode_uint32(encoded + junk)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can decode at an offset" do
      raw2, read = described_class.decode_uint32(junk + encoded + junk, junk.bytesize)
      expect(raw2).to eq(raw)
      expect(read).to eq(encoded.bytesize)
    end

    it "can encode" do
      encoded2 = described_class.encode_uint32(raw)
      expect(encoded2).to eq(encoded)
    end
  end

  describe("options") do
    test_cases = []

    test_cases << [
      :normal,                                    # name
      {"k1" => "v1", "k2" => true, "k3" => "v3"}, # raw
      [                                           # encoded
        "\x00\x00\x00\x2a",
        "\x00\x00\x00\x02", "k1",
        "\x00\x00\x00\x06", "\x00\x00\x00\x02", "v1",
        "\x00\x00\x00\x02", "k2",
        "\x00\x00\x00\x00",
        "\x00\x00\x00\x02", "k3",
        "\x00\x00\x00\x06", "\x00\x00\x00\x02", "v3",
      ].join
    ]

    test_cases << [
      :empty,            # name
      {},                # raw
      "\x00\x00\x00\x00" # encoded
    ]

    test_cases.each do |name, raw, encoded|
      describe("#{name} values") do
        it "can decode" do
          raw2, read = described_class.decode_options(encoded + junk)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can at an offset" do
          raw2, read = described_class.decode_options(junk + encoded + junk, junk.bytesize)
          expect(raw2).to eq(raw)
          expect(read).to eq(encoded.bytesize)
        end

        it "can encode" do
          encoded2 = described_class.encode_options(raw)
          expect(encoded2).to eq(encoded)
        end
      end
    end
  end

  describe("#decode_n_strings") do
    it "can decode a series of strings" do
      strs = %w(one two three)
      encoded = strs.map { |s| described_class.encode_string(s) }.join
      decoded, read = described_class.decode_n_strings(encoded, 0, 2)
      expect(decoded).to eq(strs[0..1])
      expect(read).to eq(encoded.bytesize - 9)

      decoded, read = described_class.decode_n_strings("", 0, 0)
      expect(decoded).to eq([])
      expect(read).to eq(0)
    end
  end
end
