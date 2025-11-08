variable "aws_region" {
  description = "Region where AWS resources are located"  # Update this value
  type = string
  default = "us-east-1"

}

variable "instanceName" {
  description = "Name of EC2 Instance"  # Update this value
  type = string
  default = "SERVER-A"

}

variable "existing_vpc" {
  description = "The name of the existing VPC for the servers"
  type = string
  default = "vpc-" # Need to update this name of VPC id
  
}

variable "existing_subnet" {
  description = "The name of the existing subnet for the OneStream Web Server"
  type = string
  default = "subnet-" # Need to update this name of subnet id
  
}

variable "existing_sg_id" {
  description = "Security group for the EC2 instance"
  #type = list(string)
  type = string
  default = "sg-" # Add security groups to this list...

}

variable "existing_iam_role" {
  description = "IAM Role for EC2 instance"
  type = string
  default = "" # Need to update this

}

variable "instanceType" {
  type = string
  default = "m6i.2xlarge"

}

variable "keyPair" {
  description = "Key pair to use for connectivity to the EC2 instances"
  type = string
  default = "" # Need to update this
  
}

variable "rootVolumeSize" {
  description = "Size in GB of Root Volume"
  type = string
  default = "75"
  
}

variable "dataVolumeSize" {
  description = "Size in GB of Data Volume"
  type = string
  default = "150"
  
}

variable "sslcertificate" {
  description = "OneStream Web Server SSL Certificate"
  type = string
  default = "RootCA.pfx"
}

variable "siteName" {
  description = "Default OneStream IIS Site Name"
  type = string
  default = "OneStream Web Server Site"
}

variable "ipAddress" {
  description = "* for unassigned IP addresses"
  type = string
  default = "*"
}

variable "protocol" {
  description = "HTTPS protocol for IIS Site"
  type = string
  default = "https"
}

variable "port" {
  description = "Port of IIS web site"
  type = number
  default = 443
}

variable "hostname" {
  description = "Update this value to desired ssl hostname of Onestream web site"
  type = string
  default = "" # update this value
}
