Pod::Spec.new do |s|
  s.name             = 'Slauth'
  s.version          = '0.7.15'
  s.summary          = 'A Swift wrapper around Slauth Rust crate'
  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/Devolutions/Slauth.git'
  s.license          = { :type => 'MIT', :file => './LICENSE' }
  s.author           = { 'Devolutions' => 'lfauvel@devolutions.net' }
  s.source           = { :git => 'https://github.com/Devolutions/Slauth.git', :tag => s.version.to_s }

	s.swift_version = '5.0'
	s.ios.deployment_target = '16.0'

	s.source_files = 'wrappers/swift/classes/**/*', 'slauth.h'
  s.vendored_libraries = 'target/universal/release/*.a', 'target/x86_64-apple-ios/release/*.a', 'target/aarch64-apple-ios/release/*.a'
end
