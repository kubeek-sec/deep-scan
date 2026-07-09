# CWE-798, CWE-732, CWE-311, CWE-284: Insecure Terraform infrastructure
# Hardcoded provider credentials, public S3 bucket w/o encryption, open SSH
# security group, and a public unencrypted RDS instance.
# Expected detecting family: iac

# ISSUE 3 (CWE-798): hardcoded credentials baked into the provider block
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAZ7QER4TXMP2KLNVB"
  secret_key = "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"
}

# ISSUE 1 (CWE-732 + CWE-311): public-read ACL and no server-side encryption
resource "aws_s3_bucket" "data" {
  bucket = "guinea-pig-public-data"
  acl    = "public-read"
  # no server_side_encryption_configuration block -> data stored unencrypted
}

# ISSUE 2 (CWE-284): SSH open to the entire internet
resource "aws_security_group" "ssh" {
  name = "allow-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ISSUE 4 (CWE-732 + CWE-311): publicly reachable, unencrypted database
resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "admin"
  password            = "Pr0d-DB-P@ssword-2026"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
