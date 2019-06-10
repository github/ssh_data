require_relative "./spec_helper"

describe SSHData::Certificate do
  let(:rsa_ca)     { SSHData::PrivateKey::RSA.generate(2048) }
  let(:dsa_ca)     { SSHData::PrivateKey::DSA.generate }
  let(:ecdsa_ca)   { SSHData::PrivateKey::ECDSA.generate("nistp256") }
  let(:ed25519_ca) { SSHData::PrivateKey::ED25519.generate }

  it "supports the deprecated Certificate.parse method" do
    expect {
      described_class.parse(fixture("rsa_leaf_for_rsa_ca-cert.pub"))
    }.not_to raise_error
  end

  it "raises on invalid signatures" do
    expect {
      described_class.parse_openssh(fixture("bad_signature-cert.pub"))
    }.to raise_error(SSHData::VerifyError)
  end

  it "doesn't validate signatures if provided unsafe_no_verify flag" do
    expect {
      described_class.parse_openssh(fixture("bad_signature-cert.pub"),
        unsafe_no_verify: true
      )
    }.not_to raise_error
  end

  it "raises on trailing data" do
    algo, b64, comment = fixture("rsa_leaf_for_rsa_ca-cert.pub").split(" ", 3)
    raw = Base64.decode64(b64)
    raw += "foobar"
    b64 = Base64.strict_encode64(raw)
    cert = [algo, b64, comment].join(" ")

    expect {
      described_class.parse_openssh(cert)
    }.to raise_error(SSHData::DecodeError)
  end

  it "raises on type mismatch" do
    _, b64, comment = fixture("rsa_leaf_for_rsa_ca-cert.pub").split(" ", 3)
    cert = [SSHData::Certificate::ALGO_ED25519, b64, comment].join(" ")

    expect {
      described_class.parse_openssh(cert)
    }.to raise_error(SSHData::DecodeError)
  end

  it "doesn't require the comment" do
    type, b64, _ = fixture("rsa_leaf_for_rsa_ca-cert.pub").split(" ", 3)
    cert = [type, b64].join(" ")

    expect {
      described_class.parse_openssh(cert)
    }.not_to raise_error
  end

  test_cases = []

  test_cases << [
    :rsa_cert,                      # name
    "rsa_leaf_for_rsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA, # algo
    SSHData::PublicKey::RSA,        # public key type
    SSHData::PublicKey::RSA         # ca key type
  ]

  test_cases << [
    :rsa_cert_sha2_256_sig,                  # name
    "rsa_leaf_for_rsa_ca_sha2_256-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA,          # algo
    SSHData::PublicKey::RSA,                 # public key type
    SSHData::PublicKey::RSA                  # ca key type
  ]

  test_cases << [
    :rsa_cert_sha2_512_sig,                  # name
    "rsa_leaf_for_rsa_ca_sha2_512-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA,          # algo
    SSHData::PublicKey::RSA,                 # public key type
    SSHData::PublicKey::RSA                  # ca key type
  ]

  test_cases << [
    :dsa_cert,                      # name
    "dsa_leaf_for_rsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_DSA, # algo
    SSHData::PublicKey::DSA,        # public key type
    SSHData::PublicKey::RSA         # ca key type
  ]

  test_cases << [
    :ecdsa_cert,                         # name
    "ecdsa_leaf_for_rsa_ca-cert.pub",    # fixture
    SSHData::Certificate::ALGO_ECDSA256, # algo
    SSHData::PublicKey::ECDSA,           # public key type
    SSHData::PublicKey::RSA              # ca key type
  ]

  test_cases << [
    :ed25519_cert,                      # name
    "ed25519_leaf_for_rsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_ED25519, # algo
    SSHData::PublicKey::ED25519,        # public key type
    SSHData::PublicKey::RSA             # ca key type
  ]

  test_cases << [
    :rsa_ca,                        # name
    "rsa_leaf_for_rsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA, # algo
    SSHData::PublicKey::RSA,        # public key type
    SSHData::PublicKey::RSA         # ca key type
  ]

  test_cases << [
    :dsa_ca,                        # name
    "rsa_leaf_for_dsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA, # algo
    SSHData::PublicKey::RSA,        # public key type
    SSHData::PublicKey::DSA         # ca key type
  ]

  test_cases << [
    :ecdsa_ca,                        # name
    "rsa_leaf_for_ecdsa_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA,   # algo
    SSHData::PublicKey::RSA,          # public key type
    SSHData::PublicKey::ECDSA         # ca key type
  ]

  test_cases << [
    :ed25519_ca,                        # name
    "rsa_leaf_for_ed25519_ca-cert.pub", # fixture
    SSHData::Certificate::ALGO_RSA,     # algo
    SSHData::PublicKey::RSA,            # public key type
    SSHData::PublicKey::ED25519         # ca key type
  ]

  test_cases.each do |name, fixture_name, algo, public_key_class, ca_key_class|
    describe(name) do
      let(:openssh) { fixture(fixture_name).strip }
      let(:comment) { SSHData.key_parts(openssh).last }

      subject { SSHData::Certificate.parse_openssh(openssh) }

      it "parses correctly" do
        expect(subject.algo).to eq(algo)
        expect(subject.nonce).to be_a(String)
        expect(subject.public_key).to be_a(public_key_class)
        expect(subject.serial).to eq(123)
        expect(subject.type).to eq(SSHData::Certificate::TYPE_USER)
        expect(subject.key_id).to eq("my-ident")
        expect(subject.valid_principals).to eq(["p1", "p2"])
        expect(subject.valid_after).to eq(SSHData::Certificate::BEGINNING_OF_TIME)
        expect(subject.valid_before).to eq(SSHData::Certificate::END_OF_TIME)
        expect(subject.critical_options).to eq({"foo" => "bar"})
        expect(subject.extensions).to eq({"permit-X11-forwarding" => true, "baz" => "qwer"})
        expect(subject.reserved).to eq("")
        expect(subject.ca_key).to be_a(ca_key_class)
        expect(subject.signature).to be_a(String)
      end

      it "encodes correctly" do
        expect(subject.openssh(comment: comment)).to eq(openssh)
      end

      it "can be signed with an RSA key" do
        expect { subject.sign(rsa_ca) }.to change {subject.signature}
        expect(subject.verify).to eq(true)
      end

      it "can be signed with an DSA key" do
        expect { subject.sign(dsa_ca) }.to change {subject.signature}
        expect(subject.verify).to eq(true)
      end

      it "can be signed with an ECDSA key" do
        expect { subject.sign(ecdsa_ca) }.to change {subject.signature}
        expect(subject.verify).to eq(true)
      end

      it "can be signed with an ED25519 key" do
        expect { subject.sign(ed25519_ca) }.to change {subject.signature}
        expect(subject.verify).to eq(true)
      end

    end
  end
end
