@available(iOS 15.0, *)
public class WebAuthnRequestResponse: NSObject, RustObject {

    var raw: OpaquePointer

    required init(raw: OpaquePointer) {
        self.raw = raw
    }

    func intoRaw() -> OpaquePointer {
        return self.raw
    }

    public func getAuthData() -> Data {
        let buffer = get_auth_data_from_response(self.raw)
        return Data(bytes: buffer.data, count: Int(buffer.len))
    }

    public func getSignature() -> Data {
        let buffer = get_signature_from_response(self.raw)
        return Data(bytes: buffer.data, count: Int(buffer.len))
    }

    public func isSuccess() -> Bool {
        return is_success(self.raw)
    }

    public func getErrorMessage() -> String {
        let cString = get_error_message(self.raw)
        let errorMessage = String(cString: cString!)
        free(cString)
        return errorMessage
    }

    public convenience init(
        rpId: String, attestationFlags: UInt8, clientDataHash: Data, privateKey: String
    ) throws {
        let clientDataHashPointer = UnsafeMutablePointer<UInt8>.allocate(
            capacity: clientDataHash.count)
        clientDataHash.copyBytes(to: clientDataHashPointer, count: clientDataHash.count)

        let r = generate_credential_request_response(
            rpId, privateKey, attestationFlags.bigEndian, clientDataHashPointer,
            UInt(clientDataHash.count))
        if r == nil {
            throw Err(message: "Invalid parameters")
        } else {
            self.init(raw: r!)
        }
        clientDataHashPointer.deallocate()
    }
}
