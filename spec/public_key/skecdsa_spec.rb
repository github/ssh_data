require_relative "../spec_helper"

describe SSHData::PublicKey::SKECDSA do
  let(:openssh_key) { SSHData::PublicKey.parse_openssh(fixture("skecdsa_leaf_for_rsa_ca.pub")) }
  let(:ec_p384_publickey) { ec_private_to_public(OpenSSL::PKey::EC.generate('secp384r1')) }

  it "can parse openssh-generate keys" do
    expect { openssh_key }.not_to raise_error
  end

  it "can be rencoded" do
    expect(openssh_key.rfc4253).to eq(fixture("skecdsa_leaf_for_rsa_ca.pub", binary: true))
  end

  it "blows up if the inner key identifier is not a security key" do
    # outer layer claims to be SK-ECDSA256, but inner key is plain ECDSA256
    malformed = [SSHData::PublicKey::ALGO_SKECDSA256, Base64.strict_encode64([
      SSHData::Encoding.encode_string(SSHData::PublicKey::ALGO_ECDSA256),
      SSHData::Encoding.encode_string(openssh_key.curve),
      SSHData::Encoding.encode_string(openssh_key.public_key_bytes),
      SSHData::Encoding.encode_string('ssh:'),
    ].join)].join(" ")

    expect {
      SSHData::PublicKey.parse_openssh(malformed)
    }.to raise_error(SSHData::DecodeError)
  end

  it "blows up if the inner key identifier has a mismatched curve" do
    # outer layer claims to be SK-ECDSA256, but inner key is SK-ECDSA256 with a P384 curve
    malformed = [SSHData::PublicKey::ALGO_SKECDSA256, Base64.strict_encode64([
      SSHData::Encoding.encode_string(SSHData::PublicKey::ALGO_SKECDSA256),
      SSHData::Encoding.encode_string('nistp384'),
      SSHData::Encoding.encode_string(ec_p384_publickey.to_der),
      SSHData::Encoding.encode_string('ssh:'),
    ].join)].join(" ")

    expect {
      SSHData::PublicKey.parse_openssh(malformed)
    }.to raise_error(SSHData::DecodeError)
  end

  described_class::OPENSSL_CURVE_NAME_FOR_CURVE.each do |ssh_curve, openssl_curve|
    describe openssl_curve do
      let(:algo) { "sk-ecdsa-sha2-#{ssh_curve}@openssh.com" }

      let(:private_key) { OpenSSL::PKey::EC.generate(openssl_curve) }
      let(:public_key)  { ec_private_to_public(private_key) }

      let(:msg)         { "hello, world!" }
      let(:digest)      { described_class::DIGEST_FOR_CURVE[ssh_curve].new }
      let(:openssl_sig) { private_key.sign(digest, msg) }
      let(:ssh_sig)     { described_class.ssh_signature(openssl_sig) }
      let(:sig)         { SSHData::Encoding.encode_signature(algo, ssh_sig) }
      let(:application) { "ssh:" }

      subject do
        described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: public_key.public_key.to_bn.to_s(2),
          application: application,
        )
      end

      it "is equal to keys with the same params" do
        expect(subject).to eq(described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: public_key.public_key.to_bn.to_s(2),
          application: application,
        ))
      end

      it "isnt equal to keys with different params" do
        other_key = OpenSSL::PKey::EC.generate(openssl_curve)

        expect(subject).not_to eq(described_class.new(
          algo: algo,
          curve: ssh_curve,
          public_key: other_key.public_key.to_bn.to_s(2),
          application: application,
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
        expect(subject.openssl.public_key).to eq(public_key.public_key)
      end

      it "can encode/decode signatures" do
        round_tripped = described_class.openssl_signature(
          described_class.ssh_signature(openssl_sig)
        )

        expect(round_tripped).to eq(openssl_sig)
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
