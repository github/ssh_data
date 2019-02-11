require "securerandom"
require_relative "./spec_helper"

describe SSHData::Encoding do
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

      data, _ = described_class.decode_public_key(with_prefix, nil, prefix.bytesize).first

      expect(data).to eq(rsa_data)
    end

    it "can skip the algo when decoding a public key" do
      raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)
      algo, offset = described_class.decode_string(raw)
      data, _ = described_class.decode_public_key(raw, algo, offset)

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

      expect(rsa_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(rsa_data[:key_data][:e]).to be_a(OpenSSL::BN)
      expect(rsa_data[:key_data][:n]).to be_a(OpenSSL::BN)

      expect(rsa_data[:serial]).to eq(123)
      expect(rsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(rsa_data[:key_id]).to eq("my-ident")
      expect(rsa_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(rsa_data[:valid_after]).to eq(0)
      expect(rsa_data[:valid_before]).to eq((2**64)-1)
      expect(rsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(rsa_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(rsa_data[:reserved]).to eq("")

      expect(rsa_data[:signature_key]).to be_a(String)
      expect(rsa_data[:signature_key].bytesize).to eq(279)

      expect(rsa_data[:signature]).to be_a(String)
      expect(rsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode DSA certificates" do
      expect(dsa_data[:algo]).to eq(SSHData::Certificate::ALGO_DSA)

      expect(dsa_data[:nonce]).to be_a(String)
      expect(dsa_data[:nonce].length).to eq(32)

      expect(dsa_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_DSA)
      expect(dsa_data[:key_data][:p]).to be_a(OpenSSL::BN)
      expect(dsa_data[:key_data][:q]).to be_a(OpenSSL::BN)
      expect(dsa_data[:key_data][:g]).to be_a(OpenSSL::BN)
      expect(dsa_data[:key_data][:y]).to be_a(OpenSSL::BN)

      expect(dsa_data[:serial]).to eq(123)
      expect(dsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(dsa_data[:key_id]).to eq("my-ident")
      expect(dsa_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(dsa_data[:valid_after]).to eq(0)
      expect(dsa_data[:valid_before]).to eq((2**64)-1)
      expect(dsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(dsa_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(dsa_data[:reserved]).to eq("")

      expect(dsa_data[:signature_key]).to be_a(String)
      expect(dsa_data[:signature_key].bytesize).to eq(279)

      expect(dsa_data[:signature]).to be_a(String)
      expect(dsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode ECDSA certificates" do
      expect(ecdsa_data[:algo]).to eq(SSHData::Certificate::ALGO_ECDSA256)

      expect(ecdsa_data[:nonce]).to be_a(String)
      expect(ecdsa_data[:nonce].length).to eq(32)

      expect(ecdsa_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_ECDSA256)
      expect(ecdsa_data[:key_data][:curve]).to eq("nistp256")
      expect(ecdsa_data[:key_data][:public_key]).to be_a(String)

      expect(ecdsa_data[:serial]).to eq(123)
      expect(ecdsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ecdsa_data[:key_id]).to eq("my-ident")
      expect(ecdsa_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(ecdsa_data[:valid_after]).to eq(0)
      expect(ecdsa_data[:valid_before]).to eq((2**64)-1)
      expect(ecdsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(ecdsa_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(ecdsa_data[:reserved]).to eq("")

      expect(ecdsa_data[:signature_key]).to be_a(String)
      expect(ecdsa_data[:signature_key].bytesize).to eq(279)

      expect(ecdsa_data[:signature]).to be_a(String)
      expect(ecdsa_data[:signature].bytesize).to eq(271)
    end

    it "can decode ED25519 certificates" do
      expect(ed25519_data[:algo]).to eq(SSHData::Certificate::ALGO_ED25519)

      expect(ed25519_data[:nonce]).to be_a(String)
      expect(ed25519_data[:nonce].length).to eq(32)

      expect(ed25519_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_ED25519)
      expect(ed25519_data[:key_data][:pk]).to be_a(String)

      expect(ed25519_data[:serial]).to eq(123)
      expect(ed25519_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ed25519_data[:key_id]).to eq("my-ident")
      expect(ed25519_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(ed25519_data[:valid_after]).to eq(0)
      expect(ed25519_data[:valid_before]).to eq((2**64)-1)
      expect(ed25519_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(ed25519_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(ed25519_data[:reserved]).to eq("")

      expect(ed25519_data[:signature_key]).to be_a(String)
      expect(ed25519_data[:signature_key].bytesize).to eq(279)

      expect(ed25519_data[:signature]).to be_a(String)
      expect(ed25519_data[:signature].bytesize).to eq(271)
    end

    it "can decode certs from RSA CAs" do
      expect(rsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(rsa_ca_data[:nonce]).to be_a(String)
      expect(rsa_ca_data[:nonce].length).to eq(32)

      expect(rsa_ca_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(rsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
      expect(rsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)

      expect(rsa_ca_data[:serial]).to eq(123)
      expect(rsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(rsa_ca_data[:key_id]).to eq("my-ident")
      expect(rsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(rsa_ca_data[:valid_after]).to eq(0)
      expect(rsa_ca_data[:valid_before]).to eq((2**64)-1)
      expect(rsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(rsa_ca_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(rsa_ca_data[:reserved]).to eq("")

      expect(rsa_ca_data[:signature_key]).to be_a(String)
      expect(rsa_ca_data[:signature_key].bytesize).to eq(279)

      expect(rsa_ca_data[:signature]).to be_a(String)
      expect(rsa_ca_data[:signature].bytesize).to eq(271)
    end

    it "can decode certs from DSA CAs" do
      expect(dsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(dsa_ca_data[:nonce]).to be_a(String)
      expect(dsa_ca_data[:nonce].length).to eq(32)

      expect(dsa_ca_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(dsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
      expect(dsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)

      expect(dsa_ca_data[:serial]).to eq(123)
      expect(dsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(dsa_ca_data[:key_id]).to eq("my-ident")
      expect(dsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(dsa_ca_data[:valid_after]).to eq(0)
      expect(dsa_ca_data[:valid_before]).to eq((2**64)-1)
      expect(dsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(dsa_ca_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(dsa_ca_data[:reserved]).to eq("")

      expect(dsa_ca_data[:signature_key]).to be_a(String)
      expect(dsa_ca_data[:signature]).to be_a(String)
    end

    it "can decode certs from ECDSA CAs" do
      expect(ecdsa_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(ecdsa_ca_data[:nonce]).to be_a(String)
      expect(ecdsa_ca_data[:nonce].length).to eq(32)

      expect(ecdsa_ca_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(ecdsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
      expect(ecdsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)

      expect(ecdsa_ca_data[:serial]).to eq(123)
      expect(ecdsa_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ecdsa_ca_data[:key_id]).to eq("my-ident")
      expect(ecdsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(ecdsa_ca_data[:valid_after]).to eq(0)
      expect(ecdsa_ca_data[:valid_before]).to eq((2**64)-1)
      expect(ecdsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(ecdsa_ca_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(ecdsa_ca_data[:reserved]).to eq("")

      expect(ecdsa_ca_data[:signature_key]).to be_a(String)
      expect(ecdsa_ca_data[:signature]).to be_a(String)
    end

    it "can decode certs from ED25519 CAs" do
      expect(ed25519_ca_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

      expect(ed25519_ca_data[:nonce]).to be_a(String)
      expect(ed25519_ca_data[:nonce].length).to eq(32)

      expect(ed25519_ca_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
      expect(ed25519_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
      expect(ed25519_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)

      expect(ed25519_ca_data[:serial]).to eq(123)
      expect(ed25519_ca_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
      expect(ed25519_ca_data[:key_id]).to eq("my-ident")
      expect(ed25519_ca_data[:valid_principals]).to eq("\x00\x00\x00\x02p1\x00\x00\x00\x02p2")
      expect(ed25519_ca_data[:valid_after]).to eq(0)
      expect(ed25519_ca_data[:valid_before]).to eq((2**64)-1)
      expect(ed25519_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
      expect(ed25519_ca_data[:extensions]).to eq("\x00\x00\x00\x15permit-X11-forwarding\x00\x00\x00\x00\x00\x00\x00\x03baz\x00\x00\x00\b\x00\x00\x00\x04qwer")
      expect(ed25519_ca_data[:reserved]).to eq("")

      expect(ed25519_ca_data[:signature_key]).to be_a(String)
      expect(ed25519_ca_data[:signature]).to be_a(String)
    end
  end

  describe("#decode_options") do
    it "can decode options" do
      opts = {"k1" => "v1", "k2" => "v2"}
      encoded = opts.reduce("") do |cum, (k, v)|
        cum + [
          described_class.encode_string(k),
          described_class.encode_string(described_class.encode_string(v))
        ].join
      end

      decoded, read = described_class.decode_options(encoded)
      expect(decoded).to eq(opts)
      expect(read).to eq(encoded.bytesize)

      decoded, read = described_class.decode_options("")
      expect(decoded).to eq({})
      expect(read).to eq(0)
    end
  end

  describe("#decode_strings") do
    it "can decode a series of strings" do
      strs = %w(one two three)
      encoded = strs.map { |s| described_class.encode_string(s) }.join
      decoded, read = described_class.decode_strings(encoded)
      expect(decoded).to eq(strs)
      expect(read).to eq(encoded.bytesize)

      decoded, read = described_class.decode_strings("")
      expect(decoded).to eq([])
      expect(read).to eq(0)
    end
  end

  describe("#decode_n_strings") do
    it "can decode a series of strings" do
      strs = %w(one two three)
      encoded = strs.map { |s| described_class.encode_string(s) }.join
      decoded, read = described_class.decode_n_strings(encoded, 2)
      expect(decoded).to eq(strs[0..1])
      expect(read).to eq(encoded.bytesize - 9)

      decoded, read = described_class.decode_n_strings("", 0)
      expect(decoded).to eq([])
      expect(read).to eq(0)
    end
  end

  describe("#decode_string") do
    it "can round trip" do
      s1 = "foobar"
      s2, read = described_class.decode_string(described_class.encode_string(s1))
      expect(s2).to eq(s1)
      expect(read).to eq(s1.length + 4)
    end
  end

  describe("#decode_mpint") do
    it "can round trip" do
      i1 = OpenSSL::BN.new(SecureRandom.bytes((rand * 100).to_i), 2)
      i2, read = described_class.decode_mpint(described_class.encode_mpint(i1))
      expect(i2).to eq(i1)
    end
  end
end
