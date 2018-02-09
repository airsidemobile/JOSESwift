Pod::Spec.new do |s|
  s.name              = "SwiftJOSE"
  s.version           = "0.0.1"
  s.license           = "Apache License, Version 2.0"
  s.summary           = "JOSE framework for Swift"
  s.authors           = { "Daniel Egger" => "daniel.egger@mohemian.com", "Carol Capek" => "carol.capek@mohemian.com", "Christoph Gigi Fuchs" => "christoph@mohemian.com" }
  s.homepage          = "https://mohemian.com"
  s.social_media_url  = "https://twitter.com/mohemian_mobile"

  s.platform          = :ios, "10.0"
  s.source            = { :git => "https://github.com/mohemian/jose-ios.git", :tag => "#{s.version}-rc1" }
  s.source_files      = "SwiftJOSE/**/*.{h,swift}"
  s.preserve_paths    = "SJCommonCrypto/*"

  s.prepare_command   = <<-CMD
                          mkdir -p SJCommonCrypto/iphoneos
                          mkdir -p SJCommonCrypto/iphonesimulator
                          cp SJCommonCrypto/iphoneos.modulemap SJCommonCrypto/iphoneos/module.modulemap
                          cp SJCommonCrypto/iphonesimulator.modulemap SJCommonCrypto/iphonesimulator/module.modulemap
                          CMD
end
