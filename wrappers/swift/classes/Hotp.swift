//
//  Hotp.swift
//  firebase
//
//  Created by Richer Archambault on 2019-04-26.
//  Copyright © 2019 Sebastien Aubin. All rights reserved.
//

import Foundation

#if canImport(SlauthFFI)
import SlauthFFI
#endif

public class Hotp: NSObject, RustObject {
	var raw: OpaquePointer
	
	required init(raw: OpaquePointer) {
		self.raw = raw
	}
	
	func intoRaw() -> OpaquePointer {
		return self.raw
	}
	
    public convenience init(uri: String) throws {
        let r = hotp_from_uri(uri)
        if r == nil {
            throw Err(message: "InvalidUri")
        } else {
            self.init(raw: r!)
        }
    }
	
	deinit {
		hotp_free(raw)
	}
	
	public func to_uri(label: String, issuer: String) -> String {
		let uri = hotp_to_uri(raw, label, issuer)
		let s = String(cString: uri!)
		free(uri)
		return s
	}
	
	public func inc() {
		hotp_inc(raw)
	}
	
	public func gen() -> String {
		let code = hotp_gen(raw)
		let s_code = String(cString: code!)
		free(code)
		return s_code
	}
	
	public func verify(code: String) -> Bool {
		return hotp_verify(raw, code)
	}
	
	public func validate_current(code: String) -> Bool {
		return hotp_validate_current(raw, code)
	}
}
