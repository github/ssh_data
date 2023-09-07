require_relative "../spec_helper"

describe SSHData::PrivateKey::ECDSA do
  let(:openssh_key) { SSHData::PrivateKey.parse(fixture("ecdsa_leaf_for_rsa_ca")) }
  let(:cert_key)    { SSHData::PrivateKey::DSA.generate.public_key }

  it "can raises AlgorithmError for unknown curves" do
    expect {
      described_class.generate("foo")
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "can parse openssh-generate keys" do
    keys = openssh_key
    expect(keys).to be_an(Array)
    expect(keys.size).to eq(1)
    expect(keys.first).to be_an(SSHData::PrivateKey::ECDSA)
  end

  SSHData::PublicKey::ECDSA::OPENSSL_CURVE_NAME_FOR_CURVE.each do |ssh_curve, openssl_curve|
    describe openssl_curve do
      let(:algo) { "ecdsa-sha2-#{ssh_curve}" }

      let(:private_key) { OpenSSL::PKey::EC.generate(openssl_curve) }
      let(:public_key)  { ec_private_to_public(private_key) }
      let(:comment)     { "asdf" }
      let(:message)     { "hello, world!" }

      subject { described_class.from_openssl(private_key) }

      it "can be generated" do
        expect {
          described_class.generate(ssh_curve)
        }.not_to raise_error
      end

      it "can sign messages" do
        expect(subject.public_key.verify(message, subject.sign(message))).to eq(true)
      end

      it "can sign messages with ALGO_ECDSA" do
        sig = subject.sign(message, algo: algo)
        expect(subject.public_key.verify(message, sig)).to eq(true)
      end

      it "raises when trying to sign with bad algo" do
        expect {
          subject.sign(message, algo: SSHData::PublicKey::ALGO_RSA)
        }.to raise_error(SSHData::AlgorithmError)
      end

      it "raises when trying to sign with bad algo" do
        expect {
          subject.issue_certificate(
            public_key: cert_key,
            key_id: "some ident",
            signature_algo: SSHData::PublicKey::ALGO_RSA
          )
        }.to raise_error(SSHData::AlgorithmError)
      end

      it "has an algo" do
        expect(subject.algo).to eq(algo)
      end

      it "has params" do
        expect(subject.curve).to eq(ssh_curve)
        expect(subject.public_key_bytes).to eq(public_key.public_key.to_bn.to_s(2))
        expect(subject.private_key_bytes).to eq(private_key.private_key)
      end

      it "has a comment" do
        expect(subject.comment).to eq("")
      end

      it "has an openssl representation" do
        expect(subject.openssl).to be_a(OpenSSL::PKey::EC)
        expect(subject.openssl.to_der).to eq(private_key.to_der)
      end

      it "has a public key" do
        expect(subject.public_key).to be_a(SSHData::PublicKey::ECDSA)
        expect(subject.public_key.openssl.to_der).to eq(public_key.to_der)
      end
    end
  end
end
