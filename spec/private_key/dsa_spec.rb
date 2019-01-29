require_relative "../spec_helper"

describe SSHData::PrivateKey::DSA do
  let(:private_key) { OpenSSL::PKey::DSA.generate(1024) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { private_key.params }
  let(:comment)     { "asdf" }

  let(:openssh_key) { SSHData::PrivateKey.parse(fixture("dsa_leaf_for_rsa_ca")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_DSA,
      p: params["p"],
      q: params["q"],
      g: params["g"],
      y: params["pub_key"],
      x: params["priv_key"],
      comment: comment,
    )
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_DSA)
  end

  it "has params" do
    expect(subject.p).to eq(params["p"])
    expect(subject.q).to eq(params["q"])
    expect(subject.g).to eq(params["g"])
    expect(subject.y).to eq(params["pub_key"])
    expect(subject.x).to eq(params["priv_key"])
  end

  it "has a comment" do
    expect(subject.comment).to eq(comment)
  end

  it "has an openssl representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::DSA)
    expect(subject.openssl.to_der).to eq(private_key.to_der)
  end

  it "has a public key" do
    expect(subject.public_key).to be_a(SSHData::PublicKey::DSA)
    expect(subject.public_key.openssl.to_der).to eq(public_key.to_der)
  end

  it "can parse openssh-generate keys" do
    keys = openssh_key
    expect(keys).to be_an(Array)
    expect(keys.size).to eq(1)
    expect(keys.first).to be_an(SSHData::PrivateKey::DSA)
  end
end
