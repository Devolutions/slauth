import Foundation
import AuthenticationServices

#if canImport(SlauthFFI)
import SlauthFFI
#endif

@available(iOS 15.0, *)
public class WebAuthnCreationResponse: NSObject {
    
	var raw: OpaquePointer
	var aaguid: String

	required init(raw: OpaquePointer, aaguid: String) {
		self.raw = raw
		self.aaguid = aaguid
	}

	func intoRaw() -> OpaquePointer {
		return self.raw
	}

    public func getPrivateKey() -> String {
        let cString = get_private_key_from_response(self.raw)
        let privateKey = String(cString: cString!)
        free(cString)
        return privateKey
    }

	public func getAttestationObject() -> Data {
	    let buffer = get_attestation_object_from_response(self.raw)
        return Data(bytes: buffer.data, count: Int(buffer.len))
	}
    
	public convenience init(aaguid: String, credentialId: Data, rpId: String, attestationFlags: UInt8, cose_algorithm_identifiers: [ASCOSEAlgorithmIdentifier]) throws  {
	    let credentialPointer = UnsafeMutablePointer<UInt8>.allocate(capacity: credentialId.count)
	    credentialId.copyBytes(to: credentialPointer, count: credentialId.count)

	    let cose_algorithm_identifiers_pointer = UnsafeMutablePointer<Int32>.allocate(capacity: cose_algorithm_identifiers.count)
        for i in 0...(cose_algorithm_identifiers.count - 1) {
            cose_algorithm_identifiers_pointer[i] = Int32(cose_algorithm_identifiers[i].rawValue)
        }

        let r = generate_credential_creation_response(aaguid, credentialPointer, UInt(credentialId.count), rpId, attestationFlags.bigEndian, cose_algorithm_identifiers_pointer, UInt(cose_algorithm_identifiers.count))
        if r == nil {
            throw Err(message: "Invalid parameters")
        } else {
            self.init(raw: r!, aaguid: aaguid)
        }
        credentialPointer.deallocate()
        cose_algorithm_identifiers_pointer.deallocate()
    }

	deinit {
		response_free(raw)
	}
}

public enum AttestationFlags: UInt8 {
    case userPresent = 1
    //Reserved for future = 2
    case userVerified = 4
    case backupEligible = 8
    case backedUp = 16
    //Reserved for future = 32
    case attestedCredentialDataIncluded = 64
    case extensionDataIncluded = 128
}
