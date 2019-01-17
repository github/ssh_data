require_relative "./spec_helper"

describe SSHCert::Encoding do
  let(:rsa_cert)     { described_class.decode_cert(fixture("rsa_leaf_for_rsa_ca-cert.pub")) }
  let(:dsa_cert)     { described_class.decode_cert(fixture("dsa_leaf_for_rsa_ca-cert.pub")) }
  let(:ecdsa_cert)   { described_class.decode_cert(fixture("ecdsa_leaf_for_rsa_ca-cert.pub")) }
  let(:ed25519_cert) { described_class.decode_cert(fixture("ed25519_leaf_for_rsa_ca-cert.pub")) }

  let(:rsa_ca_cert)     { described_class.decode_cert(fixture("rsa_leaf_for_rsa_ca-cert.pub")) }
  let(:dsa_ca_cert)     { described_class.decode_cert(fixture("rsa_leaf_for_dsa_ca-cert.pub")) }
  let(:ecdsa_ca_cert)   { described_class.decode_cert(fixture("rsa_leaf_for_ecdsa_ca-cert.pub")) }
  let(:ed25519_ca_cert) { described_class.decode_cert(fixture("rsa_leaf_for_ed25519_ca-cert.pub")) }

  it "can decode RSA certificates" do
    expect(rsa_cert[:key_type]).to be_a(String)
    expect(rsa_cert[:key_type]).to eq(SSHCert::RSA_CERT_TYPE)

    expect(rsa_cert[:nonce]).to be_a(String)
    expect(rsa_cert[:nonce].length).to eq(32)

    expect(rsa_cert[:e]).to be_a(OpenSSL::BN)
    expect(rsa_cert[:e]).not_to eq(OpenSSL::BN.new(0))

    expect(rsa_cert[:n]).to be_a(OpenSSL::BN)
    expect(rsa_cert[:n]).not_to eq(OpenSSL::BN.new(0))

    expect(rsa_cert[:serial]).to be_a(Integer)
    expect(rsa_cert[:serial]).to eq(123)

    expect(rsa_cert[:type]).to be_a(Integer)
    expect(rsa_cert[:type]).to eq(SSHCert::TYPE_USER)

    expect(rsa_cert[:key_id]).to be_a(String)
    expect(rsa_cert[:key_id]).to eq("my-ident")

    expect(rsa_cert[:valid_principals]).to be_a(String)
    expect(rsa_cert[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")

    expect(rsa_cert[:valid_after]).to be_a(Integer)
    expect(rsa_cert[:valid_after]).to eq(0)

    expect(rsa_cert[:valid_before]).to be_a(Integer)
    expect(rsa_cert[:valid_before]).to eq((2**64)-1)

    expect(rsa_cert[:critical_options]).to be_a(String)
    expect(rsa_cert[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")

    expect(rsa_cert[:extensions]).to be_a(String)
    expect(rsa_cert[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")

    expect(rsa_cert[:reserved]).to be_a(String)
    expect(rsa_cert[:reserved]).to eq("")

    expect(rsa_cert[:signature_key]).to be_a(String)

    expect(rsa_cert[:signed_data]).to be_a(String)
    expect(rsa_cert[:signed_data].bytesize).to eq(728)

    expect(rsa_cert[:signature]).to be_a(String)
  end

  it "can decode DSA certificates" do
    expect(dsa_cert[:key_type]).to be_a(String)
    expect(dsa_cert[:key_type]).to eq(SSHCert::DSA_CERT_TYPE)

    expect(dsa_cert[:nonce]).to be_a(String)
    expect(dsa_cert[:nonce].length).to eq(32)

    expect(dsa_cert[:p]).to be_a(OpenSSL::BN)
    expect(dsa_cert[:p]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_cert[:q]).to be_a(OpenSSL::BN)
    expect(dsa_cert[:q]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_cert[:g]).to be_a(OpenSSL::BN)
    expect(dsa_cert[:g]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_cert[:y]).to be_a(OpenSSL::BN)
    expect(dsa_cert[:y]).not_to eq(OpenSSL::BN.new(0))

    expect(dsa_cert[:serial]).to be_a(Integer)
    expect(dsa_cert[:serial]).to eq(123)

    expect(dsa_cert[:type]).to be_a(Integer)
    expect(dsa_cert[:type]).to eq(SSHCert::TYPE_USER)

    expect(dsa_cert[:key_id]).to be_a(String)
    expect(dsa_cert[:key_id]).to eq("my-ident")

    expect(dsa_cert[:valid_principals]).to be_a(String)
    expect(dsa_cert[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")

    expect(dsa_cert[:valid_after]).to be_a(Integer)
    expect(dsa_cert[:valid_after]).to eq(0)

    expect(dsa_cert[:valid_before]).to be_a(Integer)
    expect(dsa_cert[:valid_before]).to eq((2**64)-1)

    expect(dsa_cert[:critical_options]).to be_a(String)
    expect(dsa_cert[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")

    expect(dsa_cert[:extensions]).to be_a(String)
    expect(dsa_cert[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")

    expect(dsa_cert[:reserved]).to be_a(String)
    expect(dsa_cert[:reserved]).to eq("")

    expect(dsa_cert[:signature_key]).to be_a(String)

    expect(dsa_cert[:signed_data]).to be_a(String)
    expect(dsa_cert[:signed_data].bytesize).to eq(883)

    expect(dsa_cert[:signature]).to be_a(String)
  end

  it "can decode ECDSA certificates" do
    expect(ecdsa_cert[:key_type]).to be_a(String)
    expect(ecdsa_cert[:key_type]).to eq(SSHCert::ECDSA_SHA2_NISTP256_CERT_TYPE)

    expect(ecdsa_cert[:nonce]).to be_a(String)
    expect(ecdsa_cert[:nonce].length).to eq(32)

    expect(ecdsa_cert[:curve]).to be_a(String)
    expect(ecdsa_cert[:curve]).to eq("nistp256")

    expect(ecdsa_cert[:public_key]).to be_a(String)
    expect(ecdsa_cert[:public_key].length).to eq(65)

    expect(ecdsa_cert[:serial]).to be_a(Integer)
    expect(ecdsa_cert[:serial]).to eq(123)

    expect(ecdsa_cert[:type]).to be_a(Integer)
    expect(ecdsa_cert[:type]).to eq(SSHCert::TYPE_USER)

    expect(ecdsa_cert[:key_id]).to be_a(String)
    expect(ecdsa_cert[:key_id]).to eq("my-ident")

    expect(ecdsa_cert[:valid_principals]).to be_a(String)
    expect(ecdsa_cert[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")

    expect(ecdsa_cert[:valid_after]).to be_a(Integer)
    expect(ecdsa_cert[:valid_after]).to eq(0)

    expect(ecdsa_cert[:valid_before]).to be_a(Integer)
    expect(ecdsa_cert[:valid_before]).to eq((2**64)-1)

    expect(ecdsa_cert[:critical_options]).to be_a(String)
    expect(ecdsa_cert[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")

    expect(ecdsa_cert[:extensions]).to be_a(String)
    expect(ecdsa_cert[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")

    expect(ecdsa_cert[:reserved]).to be_a(String)
    expect(ecdsa_cert[:reserved]).to eq("")

    expect(ecdsa_cert[:signature_key]).to be_a(String)

    expect(ecdsa_cert[:signed_data]).to be_a(String)
    expect(ecdsa_cert[:signed_data].bytesize).to eq(553)

    expect(ecdsa_cert[:signature]).to be_a(String)
  end

  it "can decode ED25519 certificates" do
    expect(ed25519_cert[:key_type]).to be_a(String)
    expect(ed25519_cert[:key_type]).to eq(SSHCert::ED25519_CERT_TYPE)

    expect(ed25519_cert[:nonce]).to be_a(String)
    expect(ed25519_cert[:nonce].length).to eq(32)

    expect(ed25519_cert[:pk]).to be_a(String)
    expect(ed25519_cert[:pk].length).to eq(32)

    expect(ed25519_cert[:serial]).to be_a(Integer)
    expect(ed25519_cert[:serial]).to eq(123)

    expect(ed25519_cert[:type]).to be_a(Integer)
    expect(ed25519_cert[:type]).to eq(SSHCert::TYPE_USER)

    expect(ed25519_cert[:key_id]).to be_a(String)
    expect(ed25519_cert[:key_id]).to eq("my-ident")

    expect(ed25519_cert[:valid_principals]).to be_a(String)
    expect(ed25519_cert[:valid_principals]).to eq("\x00\x00\x00\x0Cmy-principal")

    expect(ed25519_cert[:valid_after]).to be_a(Integer)
    expect(ed25519_cert[:valid_after]).to eq(0)

    expect(ed25519_cert[:valid_before]).to be_a(Integer)
    expect(ed25519_cert[:valid_before]).to eq((2**64)-1)

    expect(ed25519_cert[:critical_options]).to be_a(String)
    expect(ed25519_cert[:critical_options]).to eq("\x00\x00\x00\x03foo\x00\x00\x00\x07\x00\x00\x00\x03bar")

    expect(ed25519_cert[:extensions]).to be_a(String)
    expect(ed25519_cert[:extensions]).to eq("\x00\x00\x00\x03baz\x00\x00\x00\x08\x00\x00\x00\x04qwer")

    expect(ed25519_cert[:reserved]).to be_a(String)
    expect(ed25519_cert[:reserved]).to eq("")

    expect(ed25519_cert[:signature_key]).to be_a(String)

    expect(ed25519_cert[:signed_data]).to be_a(String)
    expect(ed25519_cert[:signed_data].bytesize).to eq(500)

    expect(ed25519_cert[:signature]).to be_a(String)
  end
end
