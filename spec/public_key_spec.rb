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
      let(:sha256_fpr) { ssh_keygen_fingerprint(name, :sha256) }
      let(:md5_fpr)    { ssh_keygen_fingerprint(name, :md5) }

      subject { described_class.parse_openssh(openssh) }

      it "generates a MD5 fingerprint matching ssh-keygen" do
        skip "Fingerprint not available" if md5_fpr.nil?
        expect(subject.fingerprint(md5: true)).to eq(md5_fpr)
      end

      it "generates a SHA256 fingerprint matching ssh-keygen" do
        skip "Fingerprint not available" if sha256_fpr.nil?
        expect(subject.fingerprint).to eq(sha256_fpr)
      end

      it "can re-encode back into authorized_keys format" do
        expect(subject.openssh(comment: comment)).to eq(openssh)
      end
    end
  end
end
