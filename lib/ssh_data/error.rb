module SSHData
  Error       = Class.new(StandardError)
  DecodeError = Class.new(Error)
  VerifyError = Class.new(Error)
end
