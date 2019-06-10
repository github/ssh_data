require_relative "../spec_helper"

describe SSHData::PrivateKey::ED25519 do
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:verify_key)  { signing_key.verify_key }
  let(:comment)     { "asdf" }
  let(:message)     { "hello, world!" }

  let(:openssh_key) { SSHData::PrivateKey.parse(fixture("ed25519_leaf_for_rsa_ca")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.to_bytes,
      sk: signing_key.to_bytes + verify_key.to_bytes,
      comment: comment,
    )
  end

  it "can be generated" do
    expect {
      described_class.generate
    }.not_to raise_error
  end

  it "can sign messages" do
    expect(subject.public_key.verify(message, subject.sign(message))).to eq(true)
  end

  it "can sign messages with ALGO_ED25519" do
    sig = subject.sign(message, algo: SSHData::PublicKey::ALGO_ED25519)
    expect(subject.public_key.verify(message, sig)).to eq(true)
  end

  it "raises when trying to sign with bad algo" do
    expect {
      subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA)
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_ED25519)
  end

  it "has params" do
    expect(subject.pk).to eq(verify_key.to_bytes)
    expect(subject.sk).to eq(signing_key.to_bytes + verify_key.to_bytes)
  end

  it "has a comment" do
    expect(subject.comment).to eq(comment)
  end

  it "has an Ed25519 representation" do
    expect(subject.ed25519_key).to be_a(Ed25519::SigningKey)
    expect(subject.ed25519_key.to_bytes).to eq(signing_key.to_bytes)
  end

  it "has a public key" do
    expect(subject.public_key).to be_a(SSHData::PublicKey::ED25519)
    expect(subject.public_key.ed25519_key.to_bytes).to eq(verify_key.to_bytes)
  end

  it "can parse openssh-generate keys" do
    keys = openssh_key
    expect(keys).to be_an(Array)
    expect(keys.size).to eq(1)
    expect(keys.first).to be_an(SSHData::PrivateKey::ED25519)
  end
end
