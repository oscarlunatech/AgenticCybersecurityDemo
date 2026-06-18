terraform {
  backend "s3" {
    bucket       = "oscarlunatech-tfstate"
    key          = "oscarlunatech/terraform.tfstate"
    region       = "us-west-2"
    encrypt      = true
    use_lockfile = true
  }
}
