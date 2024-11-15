//
//  RustObject.swift
//  firebase
//
//  Created by Richer Archambault on 2019-04-26.
//  Copyright © 2019 Sebastien Aubin. All rights reserved.
//

import Foundation

protocol RustObject {
	init(raw: OpaquePointer)
	func intoRaw() -> OpaquePointer
}

struct Err: Error {
    let message: String
}
