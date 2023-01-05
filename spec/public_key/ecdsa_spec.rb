require_relative "../spec_helper"

describe SSHData::PublicKey::ECDSA do
  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("ecdsa_leaf_for_rsa_ca.pub")) }

  it "can parse openssh-generate keys" do
    expect { openssh_key }.not_to raise_error
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("ecdsa_leaf_for_rsa_ca.pub", binary: true))
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse_openssh(fixture("rsa_leaf_for_ecdsa_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error

  end

  it "blows up if the curve doesn't match the key type" do
    # outer layer claims to be p384, but curve and public key are p256
    malformed = [SSHData::PublicKey::ALGO_ECDSA384, Base64.strict_encode64([
      SSHData::Encoding.encode_string(SSHData::PublicKey::ALGO_ECDSA384),
      SSHData::Encoding.encode_string(openssh_key.curve),
      SSHData::Encoding.encode_string(openssh_key.public_key_bytes),
    ].join)].join(" ")

    expect {
      SSHData::PublicKey.parse_openssh(malformed)
    }.to raise_error(SSHData::DecodeError)
  end

  described_class::OPENSSL_CURVE_NAME_FOR_CURVE.each do |ssh_curve, openssl_curve|
    describe openssl_curve do
      let(:algo) { "ecdsa-sha2-#{ssh_curve}" }

      let(:private_key) { OpenSSL::PKey::EC.generate(openssl_curve) }
      let(:public_key)  { ec_private_to_public(private_key) }

      let(:msg)         { "hello, world!" }
      let(:digest)      { described_class::DIGEST_FOR_CURVE[ssh_curve].new }
      let(:openssl_sig) { private_key.sign(digest, msg) }
      let(:ssh_sig)     { described_class.ssh_signature(openssl_sig) }
      let(:sig)         { SSHData::Encoding.encode_signature(algo, ssh_sig) }

      subject do
        described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: public_key.public_key.to_bn.to_s(2)
        )
      end

      it "is equal to keys with the same params" do
        expect(subject).to eq(described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: public_key.public_key.to_bn.to_s(2)
        ))
      end

      it "isnt equal to keys with different params" do
        other_key = OpenSSL::PKey::EC.generate(openssl_curve)

        expect(subject).not_to eq(described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: other_key.public_key.to_bn.to_s(2)
        ))
      end

      it "has an algo" do
        expect(subject.algo).to eq(algo)
      end

      it "has parameters" do
        expect(subject.curve).to eq(ssh_curve)
        expect(subject.public_key_bytes).to eq(public_key.public_key.to_bn.to_s(2))
      end

      it "has an openssl representation" do
        expect(subject.openssl).to be_a(OpenSSL::PKey::EC)
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
        expect(subject.verify("wrong", sig)).to be(false)
      end

      it "blows up parsing malformed keys" do
        malformed = [algo, Base64.strict_encode64([
          SSHData::Encoding.encode_string(algo),
          SSHData::Encoding.encode_string(ssh_curve),
          SSHData::Encoding.encode_string(subject.public_key_bytes[0...-1]),
        ].join)].join(" ")

        expect {
          SSHData::PublicKey.parse_openssh(malformed)
        }.to raise_error(SSHData::DecodeError)
      end
    end
  end
end
