require_relative "./spec_helper"

describe SSHData::PrivateKey do
  (Dir["spec/fixtures/*for_rsa_ca"] + Dir["spec/fixtures/*.pem"]).each do |path|
    name = File.basename(path)

    describe name do
      let(:sha256_fpr) { ssh_keygen_fingerprint(name, :sha256, priv: true) }
      let(:md5_fpr)    { ssh_keygen_fingerprint(name, :md5,    priv: true) }

      subject { described_class.parse(fixture(name)).first }

      it "can parse" do
        expect { subject }.not_to raise_error
      end

      it "generates a MD5 fingerprint matching ssh-keygen" do
        expect(subject.public_key.fingerprint(md5: true)).to eq(md5_fpr)
      end

      it "generates a SHA256 fingerprint matching ssh-keygen" do
        expect(subject.public_key.fingerprint).to eq(sha256_fpr)
      end
    end
  end

  it "raises on unknown PEM types" do
    expect {
      described_class.parse(<<-PEM.gsub(/^ /, ""))
      -----BEGIN FOOBAR-----
      asdf
      -----END FOOBAR-----
    PEM
    }.to raise_error(SSHData::AlgorithmError)
  end
end
