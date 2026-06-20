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
