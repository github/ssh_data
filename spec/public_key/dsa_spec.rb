require_relative "../spec_helper"

describe SSHData::PublicKey::DSA do
  let(:private_key) { SSHData::PrivateKey::DSA.generate.openssl }
  let(:public_key)  { private_key.public_key }
  let(:params)      { public_key.params }

  let(:msg)         { "hello, world!" }
  let(:digest)      { OpenSSL::Digest::SHA1.new }
  let(:openssl_sig) { private_key.sign(digest, msg) }
  let(:ssh_sig)     { described_class.ssh_signature(openssl_sig) }
  let(:sig)         { SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_DSA, ssh_sig) }

  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("dsa_leaf_for_rsa_ca.pub")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_DSA,
      p: params["p"],
      q: params["q"],
      g: params["g"],
      y: params["pub_key"]
    )
  end

  it "is equal to keys with the same params" do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_DSA,
      p: params["p"],
      q: params["q"],
      g: params["g"],
      y: params["pub_key"]
    ))
  end

  it "isnt equal to keys with different params" do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_DSA,
      p: params["p"] + 1,
      q: params["q"],
      g: params["g"],
      y: params["pub_key"]
    ))
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_DSA)
  end

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

  it "can encode/decode signatures" do
    round_tripped = described_class.openssl_signature(
      described_class.ssh_signature(openssl_sig)
    )

    expect(round_tripped).to eq(openssl_sig)
  end

  it "can encode/decode left padded signatures" do
    sig = "\x00" + "A" * 39

    round_tripped = described_class.ssh_signature(
      described_class.openssl_signature(sig)
    )

    expect(round_tripped).to eq(sig)
  end

  it "can verify signatures" do
    expect(subject.verify(msg, sig)).to be(true)
    expect(subject.verify("wrong", sig)).to be(false)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key }.not_to raise_error
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("dsa_leaf_for_rsa_ca.pub", binary: true))
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse_openssh(fixture("rsa_leaf_for_dsa_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error
  end
end
