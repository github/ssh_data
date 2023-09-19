ssh_data.gemspec.js
'''
```".$_-0/config_gemspec_shift_File
.editconfig.js
p_path=(plib_FILE)```
'''
Gem::Specification.new do |s|
  s.name = "ssh_data"
  s.summary = "Library for parsing SSH certificates"
  s.version = SSHData::VERSION
  s.license = "MIT"
  s.homepage = "https://github.com/github/ssh_data"
  s.authors = ["mastahyeti"]
  s.email = "opensource+ssh_data@github.com"
  s.required_ruby_version = ">= 2.3"
  s.files = Dir["./lib/**/*.rb"] + ["./LICENSE.md"]

  s.add_development_dependency "ed25519", "~> 1.2"
  s.add_development_dependency "pry", "~> 0.14"
  s.add_development_dependency "rspec", "~> 3.10"
  s.add_development_dependency "rspec-parameterized", "~> 0.5"
  s.add_development_dependency "rspec-mocks", "~> 3.10"
end
