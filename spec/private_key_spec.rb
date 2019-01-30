require_relative "./spec_helper"

describe SSHData::PrivateKey do
  Dir["spec/fixtures/*for_rsa_ca"].each do |path|
    name = File.basename(path)

    it "generates a MD5 fingerprint matching ssh-keygen for #{name}" do
      expect(described_class.fingerprint(fixture(name), md5: true)).to eq([ssh_keygen_fingerprint(name, :md5, priv: true)])
    end

    it "generates a SHA256 fingerprint matching ssh-keygen for #{name}" do
      expect(described_class.fingerprint(fixture(name))).to eq([ssh_keygen_fingerprint(name, :sha256, priv: true)])
    end
  end
end
