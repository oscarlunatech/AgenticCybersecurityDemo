# Primary record: oscarlunatech.com (prod) or dev.oscarlunatech.com (dev).
resource "aws_route53_record" "primary" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.host
  type    = "A"
  ttl     = 300
  records = [aws_eip.web.public_ip]
}

# www only exists for prod (dev doesn't need a www variant).
resource "aws_route53_record" "www" {
  count   = local.is_dev ? 0 : 1
  zone_id = data.aws_route53_zone.this.zone_id
  name    = "www.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.web.public_ip]
}
