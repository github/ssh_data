
Gem::Specification.new do |s|
  s.name    = "ssh_data"
  s.summary = "Library for parsing SSH certificates"
  s.version = "0.0.1"
  s.authors = ["mastahyeti"]
  s.required_ruby_version = "~> 2.3"
  s.files = Dir["./lib/**/*.rb"]

  s.add_development_dependency "ed25519", "~> 1.2.4"
  s.add_development_dependency "pry", "~> 0.10.4"
  s.add_development_dependency "rspec", "~> 3.5.0"
  s.add_development_dependency "rspec-mocks", "~> 3.5.0"
end
