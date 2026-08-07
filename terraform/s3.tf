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

# The generic lab target image's build context (`lab-authoring`) — ONE image behind
# every challenge (supervisor + the baked challenge apps under challenges/<id>/). Like
# the static web files, it lives here rather than inlined in user_data. The box fetches
# it with the read-only key and builds `lab-authoring:latest` locally at boot (see
# user_data.sh.tftpl). `**` walks the nested tree; the relative path becomes the key
# under authoring/, and source_hash re-uploads any file that changes.
resource "aws_s3_object" "authoring_target" {
  for_each    = fileset("${path.module}/../lab/targets/authoring", "**")
  bucket      = aws_s3_bucket.artifacts.id
  key         = "authoring/${each.value}"
  source      = "${path.module}/../lab/targets/authoring/${each.value}"
  source_hash = filemd5("${path.module}/../lab/targets/authoring/${each.value}")
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

# Authored challenges (Phase 9). Same treatment as challenges.js and for the same
# reason: server.js is inlined against the 16 KB cap, and this file grows (spec
# validation now, the LangGraph authoring loop next). Readable source, fetched by key.
resource "aws_s3_object" "authoring_js" {
  bucket      = aws_s3_bucket.artifacts.id
  key         = "orchestrator/authoring.js"
  source      = "${path.module}/../lab/orchestrator/authoring.js"
  source_hash = filemd5("${path.module}/../lab/orchestrator/authoring.js")
}
