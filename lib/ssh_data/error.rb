module SSHData
  Error            = Class.new(StandardError)
  DecodeError      = Class.new(Error)
  VerifyError      = Class.new(Error)
  AlgorithmError   = Class.new(Error)
  DecryptError     = Class.new(Error)
  UnsupportedError = Class.new(Error)
end
