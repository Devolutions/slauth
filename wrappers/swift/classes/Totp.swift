//
//  Totp.swift
//  firebase
//
//  Created by Richer Archambault on 2019-04-26.
//  Copyright © 2019 Sebastien Aubin. All rights reserved.
//

import Foundation

public class Totp: NSObject, RustObject {
	var raw: OpaquePointer
	
	required init(raw: OpaquePointer) {
		self.raw = raw
	}
	
	func intoRaw() -> OpaquePointer {
		return self.raw
	}
	
	public convenience init(uri: String) throws {
		let r = totp_from_uri(uri)
        if r == nil {
            throw Err(message: "InvalidUri")
        } else {
            self.init(raw: r!)
        }
	}
	
	deinit {
		totp_free(raw)
	}
	
	public func to_uri(label: String, issuer: String) -> String {
		let uri = totp_to_uri(raw, label, issuer)
		let s = String(cString: uri!)
		free(uri)
		return s
	}
	
	public func gen() -> String {
		let code = totp_gen(raw)
		let s = String(cString: code!)
		free(code)
		return s
	}
	
	public func gen_with(elapsed: UInt) -> String {
		let code = totp_gen_with(raw, elapsed)
		let s = String(cString: code!)
		free(code)
		return s
	}
	
	public func verify(code: String) -> Bool {
		return totp_verify(raw, code)
	}
	
	public func validate_current(code: String) -> Bool {
		return totp_validate_current(raw, code)
	}
}
