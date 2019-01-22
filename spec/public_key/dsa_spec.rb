require_relative "../spec_helper"

describe SSHData::PublicKey::DSA do
  let(:private_key) { OpenSSL::PKey::DSA.generate(2048) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { public_key.params }

  let(:cert)   { SSHData::Certificate.parse(fixture("rsa_leaf_for_dsa_ca-cert.pub"), unsafe_no_verify: true) }
  let(:ca_key) { cert.ca_key }

  subject { described_class.new(p: params["p"], q: params["q"], g: params["g"], y: params["pub_key"]) }

  it "has parameters" do
    expect(subject.p).to eq(params["p"])
    expect(subject.q).to eq(params["q"])
    expect(subject.g).to eq(params["g"])
    expect(subject.y).to eq(params["pub_key"])
  end

  it "has an openssl representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::DSA)
    expect(subject.openssl.to_der).to eq(public_key.to_der)
  end

  it "can parse openssh-generate keys" do
    expect(ca_key).to be_a(described_class)
    expect { ca_key.openssl }.not_to raise_error
  end
end
