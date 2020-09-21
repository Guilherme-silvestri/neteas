output "name" {
    value = "${aws_instance.dev5.id}"
}

output "ip" {
    value = "${aws_instance.dev5.public_ip}"
}