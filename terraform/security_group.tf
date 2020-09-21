resource "aws_security_group" "acesso-ssh" {
  name        = "acesso-ssh"
  description = "acesso-ssh"


  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.cdirs_acesso_remoto
  }
  tags = {
    Name = "ssh"
  }
}


resource "aws_security_group" "acesso-ssh-aws-east-2" {
  provider = "aws.aws-east-2"
  name        = "acesso-ssh"
  description = "acesso-ssh"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.cdirs_acesso_remoto
  }
  tags = {
    Name = "ssh"
  }
}