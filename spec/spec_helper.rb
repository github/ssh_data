require "ssh_data"
require "ed25519"
require "rspec-parameterized"

RSpec.configure do |config|
  config.color_mode = :off
end

REPO_PATH    = File.expand_path(File.join(__FILE__, "..", ".."))
FIXTURE_PATH = File.expand_path(File.join(REPO_PATH, "spec", "fixtures"))

def fixture(name, binary: false, pem: false)
  data = File.read(File.join(FIXTURE_PATH, name))
  return data unless binary

  if pem
    SSHData::Encoding.decode_pem(data, "OPENSSH PRIVATE KEY")
  else
    SSHData.key_parts(data)[1]
  end
end

def ssh_keygen_fingerprint(name, algo, priv: false)
  out = `ssh-keygen #{"-e" if priv} -E #{algo} -l -f #{File.join(FIXTURE_PATH, name)}`
  out.split(":", 2).last.split(" ").first
end
