# Standalone security group rule exposing MySQL to the entire internet.
resource "aws_security_group" "database" {
  name = "baseline-database"
}

resource "aws_security_group_rule" "mysql_world" {
  type              = "ingress"
  security_group_id = aws_security_group.database.id
  protocol          = "tcp"
  from_port         = 3306
  to_port           = 3306
  cidr_blocks       = ["0.0.0.0/0"]
}
