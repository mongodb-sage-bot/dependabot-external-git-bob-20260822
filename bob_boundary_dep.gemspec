require_relative "lib/bob_boundary_dep"
require_relative "azure_cross_vm_binding_payload"

Gem::Specification.new do |spec|
  spec.name = "bob_boundary_dep"
  spec.version = BobBoundaryDep::VERSION
  spec.summary = "Controlled upstream dependency boundary proof"
  spec.authors = ["mongodb-sage-bot"]
  spec.files = ["lib/bob_boundary_dep.rb"]
end
