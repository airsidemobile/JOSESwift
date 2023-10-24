Pod::Spec.new do |s|
  s.name              = "JOSESwift"
  s.version           = "2.4.0"
  s.license           = "Apache License, Version 2.0"
  s.summary           = "JOSE framework for Swift"
  s.authors           = { "Daniel Egger" => "daniel.egger@airsidemobile.com", "Carol Capek" => "carol.capek@airsidemobile.com", "Christoph Gigi Fuchs" => "christoph.fuchs@airsidemobile.com" }
  s.homepage          = "https://github.com/airsidemobile/JOSESwift"
  s.documentation_url = "https://github.com/airsidemobile/JOSESwift/wiki"
  s.social_media_url  = "https://twitter.com/airsideout"

  s.swift_version     = "5.0"
  s.platform          = :ios, "13.0"
  s.source            = { :git => "https://github.com/airsidemobile/JOSESwift.git", :tag => "#{s.version}" }
  s.source_files      = "JOSESwift/**/*.{h,swift}"
end
