require_relative "../spec_helper"

describe SSHData::PublicKey::ECDSA do
  let(:openssh_key) { SSHData::PublicKey.parse(fixture("ecdsa_leaf_for_rsa_ca.pub")) }

  described_class::OPENSSL_CURVE_NAME_FOR_CURVE.each do |ssh_curve, openssl_curve|
    describe openssl_curve do
      let(:algo) { "ecdsa-sha2-#{ssh_curve}" }

      let(:private_key) { OpenSSL::PKey::EC.new(openssl_curve).tap(&:generate_key) }
      let(:public_key)  { OpenSSL::PKey::EC.new(private_key.to_der).tap { |k| k.private_key = nil } }

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

      it "has an algo" do
        expect(subject.algo).to eq(algo)
      end

      it "has parameters" do
        expect(subject.curve).to eq(ssh_curve)
        expect(subject.public_key).to eq(public_key.public_key.to_bn.to_s(2))
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
    end
  end

  it "can parse openssh-generate keys" do
    expect { openssh_key.openssl }.not_to raise_error
  end

  it "can verify certificate signatures" do
    expect {
      SSHData::Certificate.parse(fixture("rsa_leaf_for_ecdsa_ca-cert.pub"),
        unsafe_no_verify: false
      )
    }.not_to raise_error

  end
end
