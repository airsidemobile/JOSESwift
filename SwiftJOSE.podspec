# NOTE: We may have to adapt this Podspec once the framework gets distributed and used via CocoaPods.

Pod::Spec.new do |s|
  s.name              = "SwiftJOSE"
  s.version           = "1.0.0"
  s.license           = "Proprietary"
  s.summary           = "JOSE framework for Swift"
  s.authors           = { "Daniel Egger" => "daniel.egger@mohemian.com", "Carol Capek" => "carol.capek@mohemian.com", "Christoph Gigi Fuchs" => "christoph@mohemian.com" }
  s.homepage          = "https://mohemian.com"
  s.social_media_url  = "https://twitter.com/mohemian_mobile"

  s.platform          = :ios, "9.0"
  s.source            = { :git => "git@github.com:mohemian/jose-ios.git", :tag => "#{s.version}" }
  s.source_files      = "SwiftJOSE/**/*.{h,swift}"
end
