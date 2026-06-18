terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Only one provider now. The us-east-1 certificate provider is gone, because
# the cert is handled by Let's Encrypt on the instance, not by ACM.
provider "aws" {
  region = var.region
}
