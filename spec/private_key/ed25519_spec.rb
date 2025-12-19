require_relative "../spec_helper"

describe SSHData::PrivateKey::ED25519 do
  let(:signing_key) { OpenSSL::PKey.generate_key("ED25519") }
  let(:verify_key)  { OpenSSL::PKey.read(signing_key.public_to_pem) }

  let(:comment)     { "asdf" }
  let(:message)     { "hello, world!" }
  let(:cert_key)    { SSHData::PrivateKey::DSA.generate.public_key }

  let(:openssh_key) { SSHData::PrivateKey.parse(fixture("ed25519_leaf_for_rsa_ca")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.raw_public_key,
      sk: signing_key.raw_private_key + verify_key.raw_public_key,
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

  it "raises when trying to sign with bad algo" do
    expect {
      subject.issue_certificate(
        public_key: cert_key,
        key_id: "some ident",
        signature_algo: SSHData::PublicKey::ALGO_RSA
      )
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_ED25519)
  end

  it "has params" do
    expect(subject.pk).to eq(verify_key.raw_public_key)
    expect(subject.sk).to eq(signing_key.raw_private_key + verify_key.raw_public_key)
  end

  it "has a comment" do
    expect(subject.comment).to eq(comment)
  end

  it "has an PKey representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::PKey)
    expect(subject.openssl.raw_private_key).to eq(signing_key.raw_private_key)
  end

  it "has a public key" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::PKey)
    expect(subject.public_key.openssl.raw_public_key).to eq(verify_key.raw_public_key)
  end

  it "can parse openssh-generate keys" do
    keys = openssh_key
    expect(keys).to be_an(Array)
    expect(keys.size).to eq(1)
    expect(keys.first).to be_an(SSHData::PrivateKey::ED25519)
  end
end
