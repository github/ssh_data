require_relative "./spec_helper"

describe SSHData::PublicKey do
  it "supports the deprecated PublicKey.parse method" do
    expect {
      described_class.parse(fixture("rsa_leaf_for_rsa_ca.pub"))
    }.not_to raise_error
  end

  Dir["spec/fixtures/*ca.pub"].each do |path|
    name = File.basename(path)

    describe name do
      let(:openssh) { fixture(name).strip }
      let(:comment) { SSHData.key_parts(openssh).last }

      subject { described_class.parse_openssh(openssh) }

      it "generates a MD5 fingerprint matching ssh-keygen" do
        expect(subject.fingerprint(md5: true)).to eq(ssh_keygen_fingerprint(name, :md5))
      end

      it "generates a SHA256 fingerprint matching ssh-keygen" do
        expect(subject.fingerprint).to eq(ssh_keygen_fingerprint(name, :sha256))
      end

      it "can re-encode back into authorized_keys format" do
        expect(subject.openssh(comment: comment)).to eq(openssh)
      end
    end
  end
end
