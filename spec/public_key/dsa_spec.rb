require_relative "../spec_helper"

describe SSHData::PublicKey::DSA do
  let(:private_key) { OpenSSL::PKey::DSA.generate(1024) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { public_key.params }

  let(:msg)         { "hello, world!" }
  let(:digest)      { OpenSSL::Digest::SHA1.new }
  let(:openssl_sig) { private_key.sign(digest, msg) }
  let(:ssh_sig)     { described_class.ssh_signature(openssl_sig) }
  let(:sig)         {
    SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_DSA, ssh_sig)
  }

  let(:openssh_key) { SSHData::PublicKey.parse(fixture("dsa_leaf_for_rsa_ca.pub")) }

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

  it "can encode/decode signatures" do
    round_tripped = described_class.openssl_signature(
      described_class.ssh_signature(openssl_sig)
    )

    expect(round_tripped).to eq(openssl_sig)
  end

  it "can verify signatures" do
    expect(subject.verify(msg, sig)).to be(true)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key.openssl }.not_to raise_error
  end

  it "can verify certificate signatures" do
    SSHData::Certificate.parse(fixture("rsa_leaf_for_dsa_ca-cert.pub"),
      unsafe_no_verify: false
    )
  end
end
