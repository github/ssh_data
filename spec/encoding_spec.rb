require_relative "./spec_helper"

describe SSHData::Encoding do
  let(:rsa_data)     { described_class.parse_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub")) }
  let(:dsa_data)     { described_class.parse_certificate(fixture("dsa_leaf_for_rsa_ca-cert.pub")) }
  let(:ecdsa_data)   { described_class.parse_certificate(fixture("ecdsa_leaf_for_rsa_ca-cert.pub")) }
  let(:ed25519_data) { described_class.parse_certificate(fixture("ed25519_leaf_for_rsa_ca-cert.pub")) }

  let(:rsa_ca_data)     { described_class.parse_certificate(fixture("rsa_leaf_for_rsa_ca-cert.pub")) }
  let(:dsa_ca_data)     { described_class.parse_certificate(fixture("rsa_leaf_for_dsa_ca-cert.pub")) }
  let(:ecdsa_ca_data)   { described_class.parse_certificate(fixture("rsa_leaf_for_ecdsa_ca-cert.pub")) }
  let(:ed25519_ca_data) { described_class.parse_certificate(fixture("rsa_leaf_for_ed25519_ca-cert.pub")) }

  it "raises on type mismatch" do
    _, cert, host = fixture("rsa_leaf_for_rsa_ca-cert.pub").split(" ", 3)
    bad_type_cert = [SSHData::Certificate::ED25519_CERT_TYPE, cert, host].join(" ")
    expect {
      described_class.parse_certificate(bad_type_cert)
    }.to raise_error(SSHData::DecodeError)
  end

  it "doesn't require the user/host names" do
    type, cert, _ = fixture("rsa_leaf_for_rsa_ca-cert.pub").split(" ", 3)
    no_host_cert = [type, cert].join(" ")
    expect {
      described_class.parse_certificate(no_host_cert)
    }.not_to raise_error
  end

  it "can decode RSA certificates" do
    expect(rsa_data[:type_string]).to eq(SSHData::Certificate::RSA_CERT_TYPE)

    expect(rsa_data[:nonce]).to be_a(String)
    expect(rsa_data[:nonce].length).to eq(32)

    expect(rsa_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(rsa_data[:key_data][:e]).not_to eq(OpenSSL::BN.new(0))

    expect(rsa_data[:key_data][:n]).to be_a(OpenSSL::BN)
    expect(rsa_data[:key_data][:n]).not_to eq(OpenSSL::BN.new(0))

    expect(rsa_data[:serial]).to eq(123)
    expect(rsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(rsa_data[:key_id]).to eq("my-ident")
    expect(rsa_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(rsa_data[:valid_after]).to eq(0)
    expect(rsa_data[:valid_before]).to eq((2**64)-1)
    expect(rsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(rsa_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(rsa_data[:reserved]).to eq("")

    expect(rsa_data[:signature_key]).to be_a(String)
    expect(rsa_data[:signature_key].bytesize).to eq(279)

    expect(rsa_data[:signed_data]).to be_a(String)
    expect(rsa_data[:signed_data].bytesize).to eq(392)

    expect(rsa_data[:signature]).to be_a(String)
    expect(rsa_data[:signature].bytesize).to eq(271)
  end

  it "can decode DSA certificates" do
    expect(dsa_data[:type_string]).to eq(SSHData::Certificate::DSA_CERT_TYPE)

    expect(dsa_data[:nonce]).to be_a(String)
    expect(dsa_data[:nonce].length).to eq(32)

    expect(dsa_data[:key_data][:p]).to be_a(OpenSSL::BN)
    expect(dsa_data[:key_data][:p]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_data[:key_data][:q]).to be_a(OpenSSL::BN)
    expect(dsa_data[:key_data][:q]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_data[:key_data][:g]).to be_a(OpenSSL::BN)
    expect(dsa_data[:key_data][:g]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_data[:key_data][:y]).to be_a(OpenSSL::BN)
    expect(dsa_data[:key_data][:y]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_data[:serial]).to eq(123)
    expect(dsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(dsa_data[:key_id]).to eq("my-ident")
    expect(dsa_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(dsa_data[:valid_after]).to eq(0)
    expect(dsa_data[:valid_before]).to eq((2**64)-1)
    expect(dsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(dsa_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(dsa_data[:reserved]).to eq("")

    expect(dsa_data[:signature_key]).to be_a(String)
    expect(dsa_data[:signature_key].bytesize).to eq(279)

    expect(dsa_data[:signed_data]).to be_a(String)
    expect(dsa_data[:signed_data].bytesize).to eq(392)

    expect(dsa_data[:signature]).to be_a(String)
    expect(dsa_data[:signature].bytesize).to eq(271)
  end

  it "can decode ECDSA certificates" do
    expect(ecdsa_data[:type_string]).to eq(SSHData::Certificate::ECDSA_SHA2_NISTP256_CERT_TYPE)

    expect(ecdsa_data[:nonce]).to be_a(String)
    expect(ecdsa_data[:nonce].length).to eq(32)

    expect(ecdsa_data[:key_data][:curve]).to be_a(String)
    expect(ecdsa_data[:key_data][:curve]).to eq("nistp256")

    expect(ecdsa_data[:key_data][:public_key]).to be_a(String)
    expect(ecdsa_data[:key_data][:public_key].length).to eq(65)

    expect(ecdsa_data[:serial]).to eq(123)
    expect(ecdsa_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(ecdsa_data[:key_id]).to eq("my-ident")
    expect(ecdsa_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ecdsa_data[:valid_after]).to eq(0)
    expect(ecdsa_data[:valid_before]).to eq((2**64)-1)
    expect(ecdsa_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ecdsa_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(ecdsa_data[:reserved]).to eq("")

    expect(ecdsa_data[:signature_key]).to be_a(String)
    expect(ecdsa_data[:signature_key].bytesize).to eq(279)

    expect(ecdsa_data[:signed_data]).to be_a(String)
    expect(ecdsa_data[:signed_data].bytesize).to eq(392)

    expect(ecdsa_data[:signature]).to be_a(String)
    expect(ecdsa_data[:signature].bytesize).to eq(271)
  end

  it "can decode ED25519 certificates" do
    expect(ed25519_data[:type_string]).to eq(SSHData::Certificate::ED25519_CERT_TYPE)

    expect(ed25519_data[:nonce]).to be_a(String)
    expect(ed25519_data[:nonce].length).to eq(32)

    expect(ed25519_data[:key_data][:pk]).to be_a(String)
    expect(ed25519_data[:key_data][:pk].length).to eq(32)

    expect(ed25519_data[:serial]).to eq(123)
    expect(ed25519_data[:type]).to eq(SSHData::Certificate::TYPE_USER)
    expect(ed25519_data[:key_id]).to eq("my-ident")
    expect(ed25519_data[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")
    expect(ed25519_data[:valid_after]).to eq(0)
    expect(ed25519_data[:valid_before]).to eq((2**64)-1)
    expect(ed25519_data[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")
    expect(ed25519_data[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")
    expect(ed25519_data[:reserved]).to eq("")

    expect(ed25519_data[:signature_key]).to be_a(String)
    expect(ed25519_data[:signature_key].bytesize).to eq(279)

    expect(ed25519_data[:signed_data]).to be_a(String)
    expect(ed25519_data[:signed_data].bytesize).to eq(392)

    expect(ed25519_data[:signature]).to be_a(String)
    expect(ed25519_data[:signature].bytesize).to eq(271)
  end

  it "can decode certs from RSA CAs" do
    expect(rsa_ca_data[:type_string]).to eq(SSHData::Certificate::RSA_CERT_TYPE)

    expect(rsa_ca_data[:nonce]).to be_a(String)
    expect(rsa_ca_data[:nonce].length).to eq(32)

    expect(rsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(rsa_ca_data[:key_data][:e]).not_to eq(OpenSSL::BN.new(0))

    expect(rsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)
    expect(rsa_ca_data[:key_data][:n]).not_to eq(OpenSSL::BN.new(0))

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

    expect(rsa_ca_data[:signed_data]).to be_a(String)
    expect(rsa_ca_data[:signed_data].bytesize).to eq(392)

    expect(rsa_ca_data[:signature]).to be_a(String)
    expect(rsa_ca_data[:signature].bytesize).to eq(271)
  end

  it "can decode certs from DSA CAs" do
    expect(dsa_ca_data[:type_string]).to eq(SSHData::Certificate::RSA_CERT_TYPE)

    expect(dsa_ca_data[:nonce]).to be_a(String)
    expect(dsa_ca_data[:nonce].length).to eq(32)

    expect(dsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(dsa_ca_data[:key_data][:e]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)
    expect(dsa_ca_data[:key_data][:n]).not_to eq(OpenSSL::BN.new(0))

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
    expect(dsa_ca_data[:signed_data]).to be_a(String)
    expect(dsa_ca_data[:signature]).to be_a(String)
  end

  it "can decode certs from ECDSA CAs" do
    expect(ecdsa_ca_data[:type_string]).to eq(SSHData::Certificate::RSA_CERT_TYPE)

    expect(ecdsa_ca_data[:nonce]).to be_a(String)
    expect(ecdsa_ca_data[:nonce].length).to eq(32)

    expect(ecdsa_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(ecdsa_ca_data[:key_data][:e]).not_to eq(OpenSSL::BN.new(0))

    expect(ecdsa_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)
    expect(ecdsa_ca_data[:key_data][:n]).not_to eq(OpenSSL::BN.new(0))

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
    expect(ecdsa_ca_data[:signed_data]).to be_a(String)
    expect(ecdsa_ca_data[:signature]).to be_a(String)
  end

  it "can decode certs from ED25519 CAs" do
    expect(ed25519_ca_data[:type_string]).to eq(SSHData::Certificate::RSA_CERT_TYPE)

    expect(ed25519_ca_data[:nonce]).to be_a(String)
    expect(ed25519_ca_data[:nonce].length).to eq(32)

    expect(ed25519_ca_data[:key_data][:e]).to be_a(OpenSSL::BN)
    expect(ed25519_ca_data[:key_data][:e]).not_to eq(OpenSSL::BN.new(0))

    expect(ed25519_ca_data[:key_data][:n]).to be_a(OpenSSL::BN)
    expect(ed25519_ca_data[:key_data][:n]).not_to eq(OpenSSL::BN.new(0))

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
    expect(ed25519_ca_data[:signed_data]).to be_a(String)
    expect(ed25519_ca_data[:signature]).to be_a(String)
  end
end
