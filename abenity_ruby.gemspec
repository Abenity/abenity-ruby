
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "abenity_ruby/version"

Gem::Specification.new do |spec|
  spec.name          = "abenity_ruby"
  spec.version       = AbenityRuby::VERSION
  spec.authors       = ["Brent Linville"]
  spec.email         = ["webmaster@abenity.com"]

  spec.summary       = %q{A Ruby library for using the Abenity API.}
  spec.description   = %q{A Ruby library for using the Abenity API. API details are online at https://abenity.com/developers/api/members}
  spec.homepage      = "https://github.com/Abenity/abenity-ruby"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 2.5.4"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "minitest", "~> 5.0"
end
