variable "domain_name" {
  description = "Apex domain registered in Route 53"
  type        = string
  default     = "oscarlunatech.com"
}

variable "region" {
  type    = string
  default = "us-west-2"
}

variable "instance_type" {
  description = "Start small; change later with a stop/start (EBS data persists)."
  type        = string
  default     = "t3.micro"
}

variable "root_volume_gb" {
  description = "Size of the gp3 EBS root volume in GiB. Can be grown later with no downtime."
  type        = number
  default     = 16
}

variable "public_key_path" {
  description = "Path to your existing local SSH PUBLIC key. Change to ~/.ssh/id_rsa.pub if that's what you have."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

locals {
  www = "www.${var.domain_name}"
}
