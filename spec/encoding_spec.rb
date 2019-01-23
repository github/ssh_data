require_relative "./spec_helper"

describe SSHData::Encoding do
  let(:rsa_key_data)     { described_class.decode_public_key(fixture("rsa_leaf_for_rsa_ca.pub",     binary: true)).first }
  let(:dsa_key_data)     { described_class.decode_public_key(fixture("dsa_leaf_for_rsa_ca.pub",     binary: true)).first }
  let(:ecdsa_key_data)   { described_class.decode_public_key(fixture("ecdsa_leaf_for_rsa_ca.pub",   binary: true)).first }
  let(:ed25519_key_data) { described_class.decode_public_key(fixture("ed25519_leaf_for_rsa_ca.pub", binary: true)).first }

  let(:rsa_cert_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
  let(:dsa_cert_data)     { described_class.decode_certificate(fixture("dsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
  let(:ecdsa_cert_data)   { described_class.decode_certificate(fixture("ecdsa_leaf_for_rsa_ca-cert.pub",   binary: true)).first }
  let(:ed25519_cert_data) { described_class.decode_certificate(fixture("ed25519_leaf_for_rsa_ca-cert.pub", binary: true)).first }

  let(:rsa_ca_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub",     binary: true)).first }
  let(:dsa_ca_data)     { described_class.decode_certificate(fixture("rsa_leaf_for_dsa_ca-cert.pub",     binary: true)).first }
  let(:ecdsa_ca_data)   { described_class.decode_certificate(fixture("rsa_leaf_for_ecdsa_ca-cert.pub",   binary: true)).first }
  let(:ed25519_ca_data) { described_class.decode_certificate(fixture("rsa_leaf_for_ed25519_ca-cert.pub", binary: true)).first }

  it "can decode a public key at an offset" do
    prefix = "foobar"
    raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)
    with_prefix = [prefix, raw].join

    data, _ = described_class.decode_public_key(with_prefix, nil, prefix.bytesize).first

    expect(data).to eq(rsa_key_data)
  end

  it "can skip the algo when decoding a public key" do
    raw = fixture("rsa_leaf_for_rsa_ca.pub", binary: true)
    algo, offset = described_class.decode_string(raw)
    data, _ = described_class.decode_public_key(raw, algo, offset)

    expect(data).to eq(rsa_key_data)
  end

  it "can decode an RSA public key" do
    expect(rsa_key_data[:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
    expect(rsa_key_data[:e]).to be_a(OpenSSL::BN)
    expect(rsa_key_data[:n]).to be_a(OpenSSL::BN)
  end

  it "can decode an DSA public key" do
    expect(dsa_key_data[:algo]).to eq(SSHData::PublicKey::ALGO_DSA)
    expect(dsa_key_data[:p]).to be_a(OpenSSL::BN)
    expect(dsa_key_data[:q]).to be_a(OpenSSL::BN)
    expect(dsa_key_data[:g]).to be_a(OpenSSL::BN)
    expect(dsa_key_data[:y]).to be_a(OpenSSL::BN)
  end

  it "can decode an ECDSA public key" do
    expect(ecdsa_key_data[:algo]).to eq(SSHData::PublicKey::ALGO_ECDSA256)
    expect(ecdsa_key_data[:curve]).to eq("nistp256")
    expect(ecdsa_key_data[:public_key]).to be_a(String)
  end

  it "can decode an ED25519 public key" do
    expect(ed25519_key_data[:algo]).to eq(SSHData::PublicKey::ALGO_ED25519)
    expect(ed25519_key_data[:pk]).to be_a(String)
  end

  it "can decode a certificate at an offset" do
    prefix = "foobar"
    raw = fixture("rsa_leaf_for_rsa_ca-cert.pub", binary: true)
    with_prefix = [prefix, raw].join

    data = described_class.decode_certificate(with_prefix, prefix.bytesize).first

    expect(data).to eq(rsa_cert_data)
  end

  it "can decode RSA certificates" do
    expect(rsa_cert_data[:algo]).to eq(SSHData::Certificate::ALGO_RSA)

    expect(rsa_cert_data[:nonce]).to be_a(String)
    expect(rsa_cert_data[:nonce].length).to eq(32)

    expect(rsa_cert_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_RSA)
    expect(rsa_cert_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(rsa_cert_data[:key_data][:n]).to be_a(OpenSSL::BN)

    expect(rsa_cert_data[:serial]).to eq(123)
    expect(rsa_cert_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(rsa_cert_data[:key_id]).to eq("my-ident")
    expect(rsa_cert_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(rsa_cert_data[:valid_after]).to eq(0)
    expect(rsa_cert_data[:valid_before]).to eq((2**64)-1)
    expect(rsa_cert_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(rsa_cert_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(rsa_cert_data[:reserved]).to eq("")

    expect(rsa_cert_data[:signature_key]).to be_a(String)
    expect(rsa_cert_data[:signature_key].bytesize).to eq(279)

    expect(rsa_cert_data[:signature]).to be_a(String)
    expect(rsa_cert_data[:signature].bytesize).to eq(271)
  end

  it "can decode DSA certificates" do
    expect(dsa_cert_data[:algo]).to eq(SSHData::Certificate::ALGO_DSA)

    expect(dsa_cert_data[:nonce]).to be_a(String)
    expect(dsa_cert_data[:nonce].length).to eq(32)

    expect(dsa_cert_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_DSA)
    expect(dsa_cert_data[:key_data][:p]).to be_a(OpenSSL::BN)
    expect(dsa_cert_data[:key_data][:q]).to be_a(OpenSSL::BN)
    expect(dsa_cert_data[:key_data][:g]).to be_a(OpenSSL::BN)
    expect(dsa_cert_data[:key_data][:y]).to be_a(OpenSSL::BN)

    expect(dsa_cert_data[:serial]).to eq(123)
    expect(dsa_cert_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(dsa_cert_data[:key_id]).to eq("my-ident")
    expect(dsa_cert_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(dsa_cert_data[:valid_after]).to eq(0)
    expect(dsa_cert_data[:valid_before]).to eq((2**64)-1)
    expect(dsa_cert_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(dsa_cert_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(dsa_cert_data[:reserved]).to eq("")

    expect(dsa_cert_data[:signature_key]).to be_a(String)
    expect(dsa_cert_data[:signature_key].bytesize).to eq(279)

    expect(dsa_cert_data[:signature]).to be_a(String)
    expect(dsa_cert_data[:signature].bytesize).to eq(271)
  end

  it "can decode ECDSA certificates" do
    expect(ecdsa_cert_data[:algo]).to eq(SSHData::Certificate::ALGO_ECDSA256)

    expect(ecdsa_cert_data[:nonce]).to be_a(String)
    expect(ecdsa_cert_data[:nonce].length).to eq(32)

    expect(ecdsa_cert_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_ECDSA256)
    expect(ecdsa_cert_data[:key_data][:curve]).to eq("nistp256")
    expect(ecdsa_cert_data[:key_data][:public_key]).to be_a(String)

    expect(ecdsa_cert_data[:serial]).to eq(123)
    expect(ecdsa_cert_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(ecdsa_cert_data[:key_id]).to eq("my-ident")
    expect(ecdsa_cert_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ecdsa_cert_data[:valid_after]).to eq(0)
    expect(ecdsa_cert_data[:valid_before]).to eq((2**64)-1)
    expect(ecdsa_cert_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ecdsa_cert_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(ecdsa_cert_data[:reserved]).to eq("")

    expect(ecdsa_cert_data[:signature_key]).to be_a(String)
    expect(ecdsa_cert_data[:signature_key].bytesize).to eq(279)

    expect(ecdsa_cert_data[:signature]).to be_a(String)
    expect(ecdsa_cert_data[:signature].bytesize).to eq(271)
  end

  it "can decode ED25519 certificates" do
    expect(ed25519_cert_data[:algo]).to eq(SSHData::Certificate::ALGO_ED25519)

    expect(ed25519_cert_data[:nonce]).to be_a(String)
    expect(ed25519_cert_data[:nonce].length).to eq(32)

    expect(ed25519_cert_data[:key_data][:algo]).to eq(SSHData::PublicKey::ALGO_ED25519)
    expect(ed25519_cert_data[:key_data][:pk]).to be_a(String)

    expect(ed25519_cert_data[:serial]).to eq(123)
    expect(ed25519_cert_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(ed25519_cert_data[:key_id]).to eq("my-ident")
    expect(ed25519_cert_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ed25519_cert_data[:valid_after]).to eq(0)
    expect(ed25519_cert_data[:valid_before]).to eq((2**64)-1)
    expect(ed25519_cert_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ed25519_cert_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(ed25519_cert_data[:reserved]).to eq("")

    expect(ed25519_cert_data[:signature_key]).to be_a(String)
    expect(ed25519_cert_data[:signature_key].bytesize).to eq(279)

    expect(ed25519_cert_data[:signature]).to be_a(String)
    expect(ed25519_cert_data[:signature].bytesize).to eq(271)
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
    expect(rsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(rsa_ca_data[:valid_after]).to eq(0)
    expect(rsa_ca_data[:valid_before]).to eq((2**64)-1)
    expect(rsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(rsa_ca_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
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
    expect(dsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(dsa_ca_data[:valid_after]).to eq(0)
    expect(dsa_ca_data[:valid_before]).to eq((2**64)-1)
    expect(dsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(dsa_ca_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
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
    expect(ecdsa_ca_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ecdsa_ca_data[:valid_after]).to eq(0)
    expect(ecdsa_ca_data[:valid_before]).to eq((2**64)-1)
    expect(ecdsa_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ecdsa_ca_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
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
    expect(ed25519_ca_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ed25519_ca_data[:valid_after]).to eq(0)
    expect(ed25519_ca_data[:valid_before]).to eq((2**64)-1)
    expect(ed25519_ca_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ed25519_ca_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(ed25519_ca_data[:reserved]).to eq("")

    expect(ed25519_ca_data[:signature_key]).to be_a(String)
    expect(ed25519_ca_data[:signature]).to be_a(String)
  end
end