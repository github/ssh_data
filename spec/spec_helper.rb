require "ssh_data"
require "ed25519"

REPO_PATH    = File.expand_path(File.join(__FILE__, "..", ".."))
FIXTURE_PATH = File.expand_path(File.join(REPO_PATH, "spec", "fixtures"))

def fixture(name, binary: false)
  data = File.read(File.join(FIXTURE_PATH, name))
  return data unless binary
  _, b64, _ = data.split(" ", 3)
    Base64.decode64(b64)
end
