require_relative "../spec_helper"

describe SSHData::PublicKey::ECDSA do
  let(:cert)   { SSHData::Certificate.parse(fixture("rsa_leaf_for_ecdsa_ca-cert.pub"), unsafe_no_verify: true) }
  let(:ca_key) { cert.ca_key }

  described_class::OPENSSL_CURVE_NAME_FOR_CURVE.each do |ssh_curve, openssl_curve|
    describe openssl_curve do
      let(:private_key) { OpenSSL::PKey::EC.new(openssl_curve).tap(&:generate_key) }
      let(:public_key)  { OpenSSL::PKey::EC.new(private_key.to_der).tap { |k| k.private_key = nil } }

      subject { described_class.new(curve: ssh_curve, public_key: public_key.public_key.to_bn.to_s(2)) }

      it "has parameters" do
        expect(subject.curve).to eq(ssh_curve)
        expect(subject.public_key).to eq(public_key.public_key.to_bn.to_s(2))
      end

      it "has an openssl representation" do
        expect(subject.openssl).to be_a(OpenSSL::PKey::EC)
        expect(subject.openssl.to_der).to eq(public_key.to_der)
      end
    end
  end

  it "can parse openssh-generate keys" do
    expect(ca_key).to be_a(described_class)
    expect { ca_key.openssl }.not_to raise_error
  end
end
