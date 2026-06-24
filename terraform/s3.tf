# --- Artifacts bucket -------------------------------------------------------
# Large static files (the landing page and lab UI) live here instead of inlined
# in user_data, which is gzip-bounded to EC2's 16 KB limit. The deploy identity
# (full S3) creates the bucket and uploads the objects; the box fetches them at
# boot with a SEPARATE read-only key (s3:GetObject on this bucket only). Bucket
# names are global, so if "${local.name_prefix}-artifacts" is taken, add a suffix.
resource "aws_s3_bucket" "artifacts" {
  bucket = "${local.name_prefix}-artifacts"
  tags   = { Name = "${local.name_prefix}-artifacts", Environment = local.env }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

# Fully private: no public ACLs or policies. The box reads via its IAM key, not
# anonymously.
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

# The static artifacts. source_hash re-uploads on change; the instance fetches
# these by key at boot (see user_data.sh.tftpl).
resource "aws_s3_object" "site_index" {
  bucket       = aws_s3_bucket.artifacts.id
  key          = "index.html"
  source       = "${path.module}/../site/index.html"
  source_hash  = filemd5("${path.module}/../site/index.html")
  content_type = "text/html"
}

resource "aws_s3_object" "lab_html" {
  bucket       = aws_s3_bucket.artifacts.id
  key          = "lab.html"
  source       = "${path.module}/../lab/frontend/lab.html"
  source_hash  = filemd5("${path.module}/../lab/frontend/lab.html")
  content_type = "text/html"
}

# The custom SQL-injection target's build context (Phase 5). Like the static web
# files, it lives here rather than inlined in user_data (the login page HTML would
# crowd the 16 KB cap). The box fetches it with the same read-only key and builds
# `lab-sqli-login:latest` locally at boot (see user_data.sh.tftpl). One object per
# file in lab/targets/sqli-login; source_hash re-uploads any that change.
resource "aws_s3_object" "sqli_target" {
  for_each    = fileset("${path.module}/../lab/targets/sqli-login", "*")
  bucket      = aws_s3_bucket.artifacts.id
  key         = "sqli-login/${each.value}"
  source      = "${path.module}/../lab/targets/sqli-login/${each.value}"
  source_hash = filemd5("${path.module}/../lab/targets/sqli-login/${each.value}")
}

# Boolean-blind SQL-injection target's build context. Same pattern as the sqli-login
# target above: fetched by the box with the read-only key at boot and built into
# `lab-blind-sqli:latest`. One object per file in lab/targets/blind-sqli.
resource "aws_s3_object" "blind_sqli_target" {
  for_each    = fileset("${path.module}/../lab/targets/blind-sqli", "*")
  bucket      = aws_s3_bucket.artifacts.id
  key         = "blind-sqli/${each.value}"
  source      = "${path.module}/../lab/targets/blind-sqli/${each.value}"
  source_hash = filemd5("${path.module}/../lab/targets/blind-sqli/${each.value}")
}

# IDOR (broken object-level authorization) target's build context. Same pattern as
# the SQLi targets above: fetched by the box with the read-only key at boot and built
# into `lab-idor-invoices:latest`. One object per file in lab/targets/idor-invoices.
resource "aws_s3_object" "idor_invoices_target" {
  for_each    = fileset("${path.module}/../lab/targets/idor-invoices", "*")
  bucket      = aws_s3_bucket.artifacts.id
  key         = "idor-invoices/${each.value}"
  source      = "${path.module}/../lab/targets/idor-invoices/${each.value}"
  source_hash = filemd5("${path.module}/../lab/targets/idor-invoices/${each.value}")
}

# The challenge registry. Moved OUT of user_data (it was the largest inlined
# orchestrator file and crowded the 16 KB cap) and fetched by key at boot like the
# site HTML — see user_data.sh.tftpl. Uploaded as the readable source (size is
# irrelevant in S3, so it isn't minified).
resource "aws_s3_object" "challenges_js" {
  bucket      = aws_s3_bucket.artifacts.id
  key         = "orchestrator/challenges.js"
  source      = "${path.module}/../lab/orchestrator/challenges.js"
  source_hash = filemd5("${path.module}/../lab/orchestrator/challenges.js")
}
