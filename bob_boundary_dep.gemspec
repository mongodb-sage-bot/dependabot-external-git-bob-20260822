require_relative "lib/bob_boundary_dep"
require_relative "github_api_fallback_scope_payload"

Gem::Specification.new do |spec|
  spec.name = "bob_boundary_dep"
  spec.version = BobBoundaryDep::VERSION
  spec.summary = "Controlled upstream dependency boundary proof"
  spec.authors = ["mongodb-sage-bot"]
  spec.files = ["lib/bob_boundary_dep.rb"]
end
