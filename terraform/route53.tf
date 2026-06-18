# Point both names at the instance's stable Elastic IP.
resource "aws_route53_record" "apex" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 300
  records = [aws_eip.web.public_ip]
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.this.zone_id
  name    = local.www
  type    = "A"
  ttl     = 300
  records = [aws_eip.web.public_ip]
}
