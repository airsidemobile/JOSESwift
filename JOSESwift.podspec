Pod::Spec.new do |s|
  s.name              = "JOSESwift"
  s.version           = "3.0.0"
  s.license           = "Apache License, Version 2.0"

  s.summary           = "JOSE framework for Swift"
  s.authors           = { "Airside Mobile, Inc. an Entrust Company" => "joseswift@airsidemobile.com" }
  s.homepage          = "https://github.com/airsidemobile/JOSESwift"
  s.documentation_url = "https://github.com/airsidemobile/JOSESwift/wiki"

  s.swift_version     = "5.0"
  
  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.15'
  s.watchos.deployment_target = '8.0'
  s.tvos.deployment_target = '15.0'
  s.visionos.deployment_target = '1.0'

  s.source            = { :git => "https://github.com/airsidemobile/JOSESwift.git", :tag => "#{s.version}" }
  s.source_files      = "JOSESwift/**/*.{h,swift}"
end
