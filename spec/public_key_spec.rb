require_relative "./spec_helper"

describe SSHData::PublicKey do
  Dir["spec/fixtures/*ca.pub"].each do |path|
    name = File.basename(path)

    it "generates a MD5 fingerprint matching ssh-keygen for #{name}" do
      expect(described_class.parse(fixture(name)).fingerprint(md5: true)).to eq(ssh_keygen_fingerprint(name, :md5))
    end

    it "generates a SHA256 fingerprint matching ssh-keygen for #{name}" do
      expect(described_class.parse(fixture(name)).fingerprint).to eq(ssh_keygen_fingerprint(name, :sha256))
    end
  end
end
