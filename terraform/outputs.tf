output "site_url" {
  value = "https://${var.domain_name}"
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
