require_relative "../spec_helper"

describe SSHData::PublicKey::RSA do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { public_key.params }

  let(:cert)   { SSHData::Certificate.parse(fixture("rsa_leaf_for_rsa_ca-cert.pub"), unsafe_no_verify: true) }
  let(:ca_key) { cert.ca_key }

  subject { described_class.new(e: params["e"], n: params["n"]) }

  it "has parameters" do
    expect(subject.e).to eq(params["e"])
    expect(subject.n).to eq(params["n"])
  end

  it "has an openssl representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::RSA)
    expect(subject.openssl.to_der).to eq(public_key.to_der)
  end

  it "can parse openssh-generate keys" do
    expect(ca_key).to be_a(described_class)
    expect { ca_key.openssl }.not_to raise_error
  end
end
