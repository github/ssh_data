require_relative "./spec_helper"

describe SSHCert::Encoding do
  let(:rsa_cert_string) { fixture("rsa_leaf_for_rsa_ca-cert.pub") }
  let(:rsa_cert)        { described_class.decode_cert(rsa_cert_string) }

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
    expect(rsa_cert[:serial]).to eq(0)

    expect(rsa_cert[:type]).to be_a(Integer)
    expect(rsa_cert[:type]).to eq(SSHCert::TYPE_USER)

    expect(rsa_cert[:key_id]).to be_a(String)
    expect(rsa_cert[:key_id]).to eq("key-id-rsa-leaf-for-rsa-ca")

    expect(rsa_cert[:valid_principals]).to be_a(String)
    expect(rsa_cert[:valid_principals]).to eq("")

    expect(rsa_cert[:valid_after]).to be_a(Integer)
    expect(rsa_cert[:valid_after]).to eq(0)

    expect(rsa_cert[:valid_before]).to be_a(Integer)
    expect(rsa_cert[:valid_before]).to eq((2**64)-1)

    expect(rsa_cert[:critical_options]).to be_a(String)
    expect(rsa_cert[:critical_options]).to eq("")

    expect(rsa_cert[:extensions]).to be_a(String)

    expect(rsa_cert[:reserved]).to be_a(String)
    expect(rsa_cert[:reserved]).to eq("")

    expect(rsa_cert[:signature_key]).to be_a(String)

    expect(rsa_cert[:signature]).to be_a(String)
  end
end
