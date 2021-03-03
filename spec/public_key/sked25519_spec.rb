require_relative "../spec_helper"

describe SSHData::PublicKey::SKED25519 do
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:verify_key)  { signing_key.verify_key }

  let(:msg)     { "hello, world!" }
  let(:raw_sig) { signing_key.sign(msg) }
  let(:sig)     { SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_SKED25519, raw_sig) }
  let(:application) { "ssh:" }

  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("sked25519_leaf_for_rsa_ca.pub")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_SKED25519,
      pk: verify_key.to_bytes,
      application: application
    )
  end

  it "is equal to keys with the same params" do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_SKED25519,
      pk: verify_key.to_bytes,
      application: application
    ))
  end

  it "isnt equal to keys with different params" do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_SKED25519,
      pk: verify_key.to_bytes.reverse,
      application: application
    ))
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_SKED25519,
      pk: verify_key.to_bytes,
      application: "something else"
    ))
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_SKED25519)
  end

  it "has parameters" do
    expect(subject.pk).to eq(verify_key.to_bytes)
  end

  it "has application" do
    expect(subject.application).to eq(application)
  end

  it "has an Ed25519 representation" do
    expect(subject.ed25519_key).to be_a(Ed25519::VerifyKey)
    expect(subject.ed25519_key.to_bytes).to eq(verify_key.to_bytes)
  end

  it "can not verify signatures" do
    expect { subject.verify(msg, sig) }.to raise_error(SSHData::UnsupportedError)
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("sked25519_leaf_for_rsa_ca.pub", binary: true))
  end
end
