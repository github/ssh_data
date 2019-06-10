require_relative "../spec_helper"

describe SSHData::PrivateKey::RSA do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { private_key.params }
  let(:message)     { "hello, world!" }

  let(:openssh_key) { SSHData::PrivateKey.parse(fixture("rsa_leaf_for_rsa_ca")) }

  subject { described_class.from_openssl(private_key) }

  it "can be generated" do
    expect {
      described_class.generate(2048)
    }.not_to raise_error
  end

  it "raises AlgorithmError on small key sizes" do
    expect {
      described_class.generate(1024)
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "can generate small keys if unsafe_allow_small_key is passed" do
    expect {
      described_class.generate(1024, unsafe_allow_small_key: true)
    }.not_to raise_error
  end

  it "can sign messages" do
    expect(subject.public_key.verify(message, subject.sign(message))).to eq(true)
  end

  it "can sign messages with ALGO_RSA" do
    sig = subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA)
    expect(subject.public_key.verify(message, sig)).to eq(true)
  end

  it "can sign messages with ALGO_RSA_SHA2_256" do
    sig = subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA_SHA2_256)
    expect(subject.public_key.verify(message, sig)).to eq(true)
  end

  it "can sign messages with ALGO_RSA_SHA2_512" do
    sig = subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA_SHA2_512)
    expect(subject.public_key.verify(message, sig)).to eq(true)
  end

  it "raises when trying to sign with bad algo" do
    expect {
      subject.sign(message, algo: SSHData::PublicKey::ALGO_DSA)
    }.to raise_error(SSHData::AlgorithmError)
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
    expect(subject.comment).to eq("")
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
    keys = openssh_key
    expect(keys).to be_an(Array)
    expect(keys.size).to eq(1)
    expect(keys.first).to be_an(SSHData::PrivateKey::RSA)
  end
end
