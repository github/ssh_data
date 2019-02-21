require_relative "../spec_helper"

describe SSHData::PublicKey::RSA do
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key)  { private_key.public_key }
  let(:params)      { public_key.params }

  let(:msg)     { "hello, world!" }
  let(:digest)  { OpenSSL::Digest::SHA1.new }
  let(:raw_sig) { private_key.sign(digest, msg) }
  let(:sig)     { SSHData::Encoding.encode_signature(SSHData::PublicKey::ALGO_RSA, raw_sig) }

  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("rsa_leaf_for_rsa_ca.pub")) }

  subject do
    described_class.new(
      algo: SSHData::PublicKey::ALGO_RSA,
      e: params["e"],
      n: params["n"]
    )
  end

  it "is equal to keys with the same params" do
    expect(subject).to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_RSA,
      e: params["e"],
      n: params["n"]
    ))
  end

  it "isnt equal to keys with different params" do
    expect(subject).not_to eq(described_class.new(
      algo: SSHData::PublicKey::ALGO_RSA,
      e: params["e"] + 1,
      n: params["n"]
    ))
  end

  it "has an algo" do
    expect(subject.algo).to eq(SSHData::PublicKey::ALGO_RSA)
  end

  it "has parameters" do
    expect(subject.e).to eq(params["e"])
    expect(subject.n).to eq(params["n"])
  end

  it "has an openssl representation" do
    expect(subject.openssl).to be_a(OpenSSL::PKey::RSA)
    expect(subject.openssl.to_der).to eq(public_key.to_der)
  end

  it "can verify signatures" do
    expect(subject.verify(msg, sig)).to be(true)
    expect(subject.verify("wrong", sig)).to be(false)
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key }.not_to raise_error
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("rsa_leaf_for_rsa_ca.pub", binary: true))
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse_openssh(fixture("rsa_leaf_for_rsa_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error
  end
end
