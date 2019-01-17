require "sshcert"

REPO_PATH    = File.expand_path(File.join(__FILE__, "..", ".."))
FIXTURE_PATH = File.expand_path(File.join(REPO_PATH, "spec", "fixtures"))

def fixture(name)
  File.read(File.join(FIXTURE_PATH, name))
end
