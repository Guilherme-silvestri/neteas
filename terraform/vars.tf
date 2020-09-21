variable "amis" {
    type = "map"
    default = {
        "us-east-1" = "ami-026c8acd92718196b"
    }
}

variable "image" {
    type = "map"
    default = {
        "image" = "t2.micro"
    }
}

variable "cdirs_acesso_remoto" {
    type = "list"
    default = ["187.3.219.219/32","187.3.219.218/32"]

}

variable "key" {
    default = "terraform-aws"
}

