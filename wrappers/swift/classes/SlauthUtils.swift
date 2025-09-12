import Foundation

public struct SlauthUtils {
     public static func convertPkcs8ToPrivateKey(pkcs8String: String) -> String {
        let cString = pkcs8_to_custom_private_key(pkcs8String)
        let privateKey = String(cString: cString!)
        free(cString)
        return privateKey
    }

    public static func convertPrivateKeyToPkcs8(privateKey: String) -> String {
        let cString = private_key_to_pkcs8_der(privateKey)
        let pkcs8String = String(cString: cString!)
        free(cString)
        return pkcs8String
    }
}