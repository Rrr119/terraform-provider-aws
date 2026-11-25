# Public access block that leaves two controls explicitly disabled.
resource "aws_s3_bucket" "weak_block" {
  bucket = "baseline-weak-block"

  public_access_block {
    block_public_acls       = true
    block_public_policy     = false
    ignore_public_acls      = true
    restrict_public_buckets = false
  }
}
