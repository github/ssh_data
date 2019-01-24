require_relative "../spec_helper"

describe SSHData::PublicKey::ED25519 do
  let(:signing_key) { Ed25519::SigningKey.generate }
  let(:verify_key)  { signing_key.verify_key }

  let(:msg)     { "hello, world!" }
  let(:raw_sig) { signing_key.sign(msg) }
  let(:sig)     { SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_ED25519, raw_sig) }

  let(:openssh_key) { SSHData::PublicKey.parse(fixture("ed25519_leaf_for_rsa_ca.pub")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.to_bytes
    )
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_ED25519)
  end

  it "has parameters" do
    expect(subject.pk).to eq(verify_key.to_bytes)
  end

  it "has an Ed25519 representation" do
    expect(subject.ed25519_key).to be_a(Ed25519::VerifyKey)
    expect(subject.ed25519_key.to_bytes).to eq(verify_key.to_bytes)
  end

  it "can verify signatures" do
    expect(subject.verify(msg, sig)).to be(true)
    expect(subject.verify("wrong", sig)).to be(false)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key.ed25519_key }.not_to raise_error
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse(fixture("rsa_leaf_for_ed25519_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error
  end

  it "fails cleanly if the ed25519 gem hasn't been loaded" do
    expect(described_class.enabled?).to be(true)
     backup = Object.send(:remove_const, :Ed25519)
     expect(described_class.enabled?).to be(false)

    begin
      expect {
        SSHData::Certificate.parse(fixture("rsa_leaf_for_ed25519_ca-cert.pub"),
          unsafe_no_verify: false
        )
      }.to raise_error(SSHData::VerifyError)
    ensure
      Object.const_set(:Ed25519, backup)
    end
  end
end
