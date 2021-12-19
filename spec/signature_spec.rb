require_relative "./spec_helper"

describe SSHData::Signature do
  describe "end to end" do
    it "can verify an Ed25519-SK git signature" do
      message= "tree ed9f16d32a89e48289d9d4becc4ff47cbd11f58c\nparent 7c6364502eceecc87b276d8b49d8eb0ae96fd9e3\nauthor Kevin Jones <octocat@github.com> 1638815753 -0500\ncommitter Kevin Jones <octocat@github.com> 1638815828 -0500\n\ntest\n"
      signature = <<~SIG
      -----BEGIN SSH SIGNATURE-----
      U1NIU0lHAAAAAQAAAEoAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAAAgnXUo8l
      URoToCMzr+Rxeia/9yy+Rn+VwTTOqXdIgf7TUAAAAEc3NoOgAAAANnaXQAAAAAAAAABnNo
      YTUxMgAAAGcAAAAac2stc3NoLWVkMjU1MTlAb3BlbnNzaC5jb20AAABAud+P+aC7yCEcgy
      smyAyN5iokI0T+dKuhl7Ml7XB/wPBlefSamMXoHE7k3BbAXBNXJQH0TtHo/aX0gZxLy44D
      DgUAAAAG
      -----END SSH SIGNATURE-----
      SIG

      subject = described_class.parse_pem(signature)
      expect(subject.verify(message)).to be(true)
    end

    it "can verify an RSA git signature" do
      message = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent 339ca5fd2a41e29236ea793772308bb054b9d81b\nauthor Kevin Jones <vcsjones@github.com> 1637774236 -0500\ncommitter Kevin Jones <vcsjones@github.com> 1637774236 -0500\n\nWHAT\n"
      signature = <<~SIG
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBANEwkDjsYE02vY+bTFXAL9
        xaGDFRwpAYutfhl7eL1Qn6dziGnokqMz1FnwPbRkPUOtdwXbojK0W45DS8rODLhvwyEJjj
        sY2L9pKX/6hKDgb1RjtNAv57OHnfW3qyZWM/Nyd5js9K+43JN1ECoWCTVqtAaJcyfNXY8Y
        FeR6x5ARkBZf+tgPA2+xIdmDf0jxyZ+hr6LRnE6/N9WsrCURnwx3u8XE8kusudBXDD4XKp
        F/AqptHwi6OML+9kRQmyXXYs1dvPaJi4TGAGlPPD7mQaWT9fsKXJZa3jl6ckzq6D7SDDPh
        CF2e/ZpzIJuusMQrx2snhKgKYh+G4WS/FpLcan+HG+/bv91lzNBXufJSLs5oo0B13L6ZaK
        CJMkzG4zo/evDiomkXv9Fg8f2bIw2Ayh56Cd4Dcc2MYfziG3yLiVQrDu2eCTuILYzYdcFw
        hzxkS8V6Ep+9U4ct0Zt+hTpyloSnQ7AEX/FKHAT7xdQxVoYaY7cVRyOWMROQ6ArxiNbPnk
        JQAAAANnaXQAAAAAAAAABnNoYTUxMgAAAZQAAAAMcnNhLXNoYTItNTEyAAABgKE+f+H3D1
        +kgPGi1TulPivysng0PIUthoVHSpJ5OKd2VrbdiH5B/XK1DmhpxCFVy6WAKD/x7a6Qpjd2
        VSVsKdtJeBLfniTWB/LJQD/5miEVBG10F9V5EaEl4uRiQrTTGEAznBg3k0yIUVBdWWjoJh
        5dLw+NQNWf9yw+/hNbtcCjkMeeZLvLwZNhsFxhRiIi5cy5m6O/eSSekaXe4sj0HxmuSIwh
        8bFRlU+JQwmJ5P1tsnyhwaSSs5qnJ0MXiDeLD5MOt9PGDJhnNarMqYkA61slhhq1XkQu1E
        FXdurNLkKaTpViSlFXqjFGXgoyB8yWB9DuqoZm69xGtCh1TmKkyE3M2R6hqXTqc90Szkxr
        POr3R0OsJrYu1VOc//AKz7AHp1DGHOTNZkpfYVzm76wrkPS9LMVieZkelcr75/az+w6kev
        qi1HNSYwD+pWej8+oCw6jri/ulGHDYyARR4ZSIR2AgBP5QZ0B0aLNr5F9ufbJvkGEpUvQH
        rfqicASU/vCBEQ==
        -----END SSH SIGNATURE-----
      SIG

      subject = described_class.parse_pem(signature)
      expect(subject.verify(message)).to be(true)
    end
  end

  describe "#verify" do

    Dir["spec/fixtures/signatures/message.*no-options.sig"].each do |path|
      name = File.basename(path)

      describe name do
        let(:signature) { File.read(path) }
        let(:data) { File.read("spec/fixtures/signatures/message") }

        it "verifies with data" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data)).to be(true)
        end

        it "does not verify with tampered data" do
          bad_data = data + "bad"
          subject = described_class.parse_pem(signature)
          expect(subject.verify(bad_data)).to be(false)
        end

        it "parses correctly" do
          subject = described_class.parse_pem(signature)
          expect(subject.sigversion).to eq(1)
          expect(subject.namespace).to eq("file")
          expect(subject.reserved).to be_empty
          expect(subject.hash_algorithm).to eq("sha512")
        end
      end
    end
  end

  describe "#verify security keys" do
    Dir["spec/fixtures/signatures/message.*-sk-*no-options.sig"].each do |path|
      name = File.basename(path)

      describe name do
        let(:signature) { File.read(path) }
        let(:data) { File.read("spec/fixtures/signatures/message") }

        it "does not verify if user verification is required" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data, user_verification_required: true)).to be(false)
        end
      end
    end
  end

  describe "#verify no-touch" do
    Dir["spec/fixtures/signatures/message.*no-touch-required.sig"].each do |path|
      name = File.basename(path)

      describe name do
        let(:signature) { File.read(path) }
        let(:data) { File.read("spec/fixtures/signatures/message") }

        it "verifies with data" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data, user_presence_required: false)).to be(true)
        end

        it "does not verify with tampered data" do
          bad_data = data + "bad"
          subject = described_class.parse_pem(signature)
          expect(subject.verify(bad_data, user_presence_required: false)).to be(false)
        end

        it "does not verify with user presence" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data, user_presence_required: true)).to be(false)
        end

        it "does not verify with user presence by default" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data)).to be(false)
        end

        it "errors on unknown verify options" do
          subject = described_class.parse_pem(signature)
          expect { subject.verify(data, potato: :no) }.to raise_error(SSHData::UnsupportedError)
        end
      end
    end
  end

  describe "#verify verify-required" do

    Dir["spec/fixtures/signatures/message.*verify-required.sig"].each do |path|
      name = File.basename(path)

      describe name do
        let(:signature) { File.read(path) }
        let(:data) { File.read("spec/fixtures/signatures/message") }

        it "verifies with data" do
          subject = described_class.parse_pem(signature)
          expect(subject.verify(data, user_verification_required: true)).to be(true)
        end

        it "does not verify with tampered data" do
          bad_data = data + "bad"
          subject = described_class.parse_pem(signature)
          expect(subject.verify(bad_data, user_verification_required: true)).to be(false)
        end
      end
    end
  end

end
