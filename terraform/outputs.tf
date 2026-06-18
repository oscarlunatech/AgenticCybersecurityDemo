output "environment" {
  value = local.env
}

output "site_url" {
  value = "https://${local.host}"
}

output "lab_url" {
  description = "The Start-demo control page"
  value       = "https://${local.host}/lab.html"
}

output "public_ip" {
  description = "Stable Elastic IP. DNS points here and survives stop/start."
  value       = aws_eip.web.public_ip
}

output "instance_id" {
  value = aws_instance.web.id
}

output "ssh_connect" {
  description = "SSH into the instance (uses your local key)"
  value       = "ssh ubuntu@${aws_eip.web.public_ip}"
}
