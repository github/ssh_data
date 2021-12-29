module SSHData
  module PublicKey
    module SecurityKey

      # Defaults to match OpenSSH, user presence is required by verification is not.
      DEFAULT_SK_VERIFY_OPTS = {
        user_presence_required: true,
        user_verification_required: false
      }

      SK_FLAG_USER_PRESENCE     = 0b001
      SK_FLAG_USER_VERIFICATION = 0b100

      def build_signing_blob(application, signed_data, signature)
        read = 0
        sig_algo, raw_sig, signature_read = Encoding.decode_signature(signature)
        read += signature_read
        sk_flags, sk_flags_read = Encoding.decode_uint8(signature, read)
        read += sk_flags_read
        counter, counter_read = Encoding.decode_uint32(signature, read)
        read += counter_read

        if read != signature.bytesize
          raise DecodeError, "unexpected trailing data"
        end

        application_hash = OpenSSL::Digest::SHA256.digest(application)
        message_hash = OpenSSL::Digest::SHA256.digest(signed_data)

        blob =
          application_hash +
          Encoding.encode_uint8(sk_flags) +
          Encoding.encode_uint32(counter) +
          message_hash

        [sig_algo, raw_sig, sk_flags, blob]
      end
    end
  end
end
