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

  it "can verify a diminished signature" do
    diminished_signature_hex =
      "0000000c7273612d736861322d323536000000ff897e8dc2fe891236d4378c10" +
      "9f438b8a431afd9573a1fc62c07748494c38200cc30f2f6438480ca317aa6e1a" +
      "c91b8352e24f325785e06e1713ee44a3b039de7af6249bac279ff887258e7dde" +
      "fa16f4f9bdbf817499c0c6ae0ef9e10fe7125215ee04091c1f03004546b45bb9" +
      "8e2240a481af97eba10175ca7a81a13300e5bd535db06eedbcb2491f76327695" +
      "75db2b36b6a1d5975e276ce308c54134a9ce0cfc255f88b010d9e07ce5624ce9" +
      "84093b2b8265bd1552709a224a64e70ef7166512d05a2719b53a9f3210f8103a" +
      "1a57fb5a2c8624775e3641b2c204f6b49b8d98fe46080dbcd6cef2fead6f22a9" +
      "5edd139db34728bce4b00ca8da03c01c653cff"
    diminished_signature = [diminished_signature_hex].pack("H*")
    content = "52b85cf8b49ec9d722f3b233215497acc2812f943c2055d92ae858da22cdebcf"

    expect(openssh_key.verify(content, diminished_signature)).to be(true)
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
