Pod::Spec.new do |s|
  s.name              = "JOSESwift"
  s.version           = "1.8.1"
  s.license           = "Apache License, Version 2.0"
  s.summary           = "JOSE framework for Swift"
  s.authors           = { "Daniel Egger" => "daniel.egger@airsidemobile.com", "Carol Capek" => "carol.capek@airsidemobile.com", "Christoph Gigi Fuchs" => "christoph.fuchs@airsidemobile.com", "Ramunas Jurgilas" => "rjur@danskebank.lt", "Marius Tamulis" => "mtamu@danskebank.lt" }
  s.homepage          = "https://github.com/airsidemobile/JOSESwift"
  s.documentation_url = "https://github.com/airsidemobile/JOSESwift/wiki"
  s.social_media_url  = "https://twitter.com/airsideout"

  s.swift_version     = "5.0"
  s.platform          = :ios, "10.0"
  s.source            = { :git => "https://github.com/mtamu/JOSESwift.git", :tag => "#{s.version}" }
  s.source_files      = "JOSESwift/**/*.{h,swift}"
end
