require_relative "./spec_helper"

describe SSHData::PrivateKey do
  (Dir["spec/fixtures/*for_rsa_ca"] + Dir["spec/fixtures/*.plaintext.pem"]).each do |path|
    name = File.basename(path)

    describe name do
      let(:sha256_fpr) { ssh_keygen_fingerprint(name, :sha256, priv: true) }
      let(:md5_fpr)    { ssh_keygen_fingerprint(name, :md5,    priv: true) }

      subject { described_class.parse(fixture(name)).first }

      it "can parse" do
        expect { subject }.not_to raise_error
      end

      it "generates a MD5 fingerprint matching ssh-keygen" do
        expect(subject.public_key.fingerprint(md5: true)).to eq(md5_fpr)
      end

      it "generates a SHA256 fingerprint matching ssh-keygen" do
        expect(subject.public_key.fingerprint).to eq(sha256_fpr)
      end

      it "can issue a certificate" do
        cert_key = SSHData::PrivateKey::ECDSA.generate("nistp256").public_key
        subject.issue_certificate(public_key: cert_key, key_id: "some ident")
      end
    end
  end

  Dir["spec/fixtures/*.encrypted.pem"].each do |path|
    name = File.basename(path)

    describe name do
      it "raises DecodeError parsing #{name}" do
        expect {
          described_class.parse(fixture(name))
        }.to raise_error(SSHData::DecryptError)
      end
    end
  end

  it "raises on unknown PEM types" do
    expect {
      described_class.parse(<<-PEM.gsub(/^ /, ""))
      -----BEGIN FOOBAR-----
      asdf
      -----END FOOBAR-----
    PEM
    }.to raise_error(SSHData::AlgorithmError)
  end

  it "raises on encrypted PEM type" do
    expect {
      described_class.parse(<<-PEM.gsub(/^ /, ""))
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIIE6TAbBgkqhkiG9w0BBQMwDgQIcWWgZeQYPTcCAggABIIEyLoa5b3ktcPmy4VB
        hHkpHzVSEsKJPmQTUaQvUwIp6+hYZeuOk78EPehrYJ/QezwJRdyBoD51oOxqWCE2
        fZ5Wf6Mi/9NIuPyqQccP2ouErcMAcDLaAx9C0Ot37yoG0S6hOZgaxqwnCdGYKHgS
        7cYUv40kLOJmTOJlHJbatfXHocrHcHkCBJ1q8wApA1KVQIZsqmyBUBuwbrfFwpC9
        d/R674XxCWJpXvU63VNZRFYUvd7YEWCrdSeleb99p0Vn1kxI5463PXurgs/7GPiO
        SLSdX44DESP9l7lXenC4gbuT8P0xQRDzGrB5l9HHoV3KMXFODWTMnLcp1nuhA0OT
        fPS2yzT9zJgqHiVKWgcUUJ5uDelVfnsmDhnh428p0GBFbniH07qREC9kq78UqQNI
        Kybp4jQ4sPs64zdYm/VyLWtAYz8QNAKHLcnPwmTPr/XlJmox8rlQhuSQTK8E+lDr
        TOKpydrijN3lF+pgyUuUj6Ha8TLMcOOwqcrpBig4SGYoB56gjAO0yTE9uCPdBakj
        yxi3ksn51ErigGM2pGMNcVdwkpJ/x+DEBBO0auy3t9xqM6LK8pwNcOT1EWO+16zY
        79LVSavc49t+XxMc3Xasz/G5xQgD1FBp6pEnsg5JhTTG/ih6Y/DQD8z3prjC3qKc
        rpL4NA9KBI/IF1iIXlrfmN/zCKbBuEOEGqwcHBDHPySZbhL2XLSpGcK/NBl1bo1Z
        G+2nUTauoC67Qb0+fnzTcvOiMNAbHMiqkirs4anHX33MKL2gR/3dp8ca9hhWWXZz
        Mkk2FK9sC/ord9F6mTtvTiOSDzpiEhb94uTxXqBhIbsrGXCUUd0QQN5s2dmW2MfS
        M35KeSv2rwDGzC1+Qf3MhHGIZDqoQwuZEzM5yHHafCatAbZd2sjaFWegg0r2ca7a
        eZkZFj3ZuDYXJFnL82guOASh7rElWO2Ys7ncXAKnaV3WkkF+JDv/CUHr+Q/h6Ae5
        qEvgubTCVSYHzRP37XJItlcdywTIcTY+t6jymmyEBJ66LmUoD47gt/vDUSbhT6Oa
        GlcZ+MZGlUnPOSq4YknOgwKH8izboY4UgVCrmXvlaZYQhZemNDkVbpYVDf+s6cPf
        tJwVoZf+qf2SsRTUsI10isoIzCyGw2ie8kmipdP434Z/99uVU3zxD6raNDlyp33q
        FWMgpr2JU6NVAla7N51g7Jk8VjIIn7SvCYyWkmvv4kLB1UHl3NFqYb9YuIZUaDyt
        j/NMcKMLLOaEorRZ2N2mDNoihMxMf8J3J9APnzUigAtaalGKNOrd2Fom5OVADePv
        Tb5sg1uVQzfcpFrjIlLVh+2cekX0JM84phbMpHmm5vCjjfYvUvcMy0clCf0x3jz6
        LZf5Fzc8xbZmpse5OnOrsDLCNh+SlcYOzsagSZq4TgvSeI9Tr4lv48dLJHCCcYKL
        eymS9nhlCFuuHbi7zI7edcI49wKUW1Sj+kvKq3LMIEkMlgzqGKA6JqSVxHP51VH5
        FqV4aKq70H6dNJ43bLVRPhtF5Bip5P7k/6KIsGTPUd54PHey+DuWRjitfheL0G2w
        GF/qoZyC1mbqdtyyeWgHtVbJVUORmpbNnXOII9duEqBUNDiO9VSZNn/8h/VsYeAB
        xryZaRDVmtMuf/OZBQ==
        -----END ENCRYPTED PRIVATE KEY-----
    PEM
    }.to raise_error(SSHData::DecryptError)
  end
end
