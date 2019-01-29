require_relative "../spec_helper"

describe SSHData::PrivateKey::RSA do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { private_key.params }

  let(:openssh_key) { SSHData::PublicKey.parse(fixture("rsa_leaf_for_rsa_ca.pub")) }

  let(:comment) { "asdf" }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_RSA,
      n: params["n"],
      e: params["e"],
      d: params["d"],
      iqmp: params["iqmp"],
      p: params["p"],
      q: params["q"],
      comment: comment,
    )
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_RSA)
  end

  it "has params" do
    expect(subject.n).to eq(params["n"])
    expect(subject.e).to eq(params["e"])
    expect(subject.d).to eq(params["d"])
    expect(subject.iqmp).to eq(params["iqmp"])
    expect(subject.p).to eq(params["p"])
    expect(subject.q).to eq(params["q"])
  end

  it "has a comment" do
    expect(subject.comment).to eq(comment)
  end

  it "has an openssl representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::RSA)
    expect(subject.openssl.to_der).to eq(private_key.to_der)
  end

  it "has a public key" do
    expect(subject.public_key).to be_a(SSHData::PublicKey::RSA)
    expect(subject.public_key.openssl.to_der).to eq(public_key.to_der)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key }.not_to raise_error
  end
end