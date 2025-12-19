require_relative "../spec_helper"

describe SSHData::PublicKey::ED25519 do
  let(:signing_key) { OpenSSL::PKey.generate_key("ED25519") }
  let(:verify_key)  { OpenSSL::PKey.read(signing_key.public_to_pem) }

  let(:msg)     { "hello, world!" }
  let(:raw_sig) { signing_key.sign(nil, msg) }
  let(:sig)     { SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_ED25519, raw_sig) }

  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("ed25519_leaf_for_rsa_ca.pub")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.raw_public_key
    )
  end

  it "is equal to keys with the same params" do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.raw_public_key
    ))
  end

  it "isnt equal to keys with different params" do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_ED25519,
      pk: verify_key.raw_public_key.reverse
    ))
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_ED25519)
  end

  it "has parameters" do
    expect(subject.pk).to eq(verify_key.raw_public_key)
  end

  it "has a pkey representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::PKey)
    expect(subject.openssl.raw_public_key).to eq(verify_key.raw_public_key)
  end

  it "can verify signatures" do
    expect(subject.verify(msg, sig)).to be(true)
    expect(subject.verify("wrong", sig)).to be(false)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key.openssl }.not_to raise_error
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("ed25519_leaf_for_rsa_ca.pub", binary: true))
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse_openssh(fixture("rsa_leaf_for_ed25519_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error
  end
end
