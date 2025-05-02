# iacs-IaCDriftDetector
A command-line tool that compares the currently deployed infrastructure state with the IaC configuration to detect configuration drift. Reports differences and potential security implications. - Focused on Utilities designed to statically analyze Infrastructure-as-Code files (e.g., Terraform, CloudFormation, Ansible playbooks) for security misconfigurations, insecure defaults, and compliance violations.

## Install
`git clone https://github.com/ShadowStrikeHQ/iacs-iacdriftdetector`

## Usage
`./iacs-iacdriftdetector [params]`

## Parameters
- `-h`: Show help message and exit
- `-i`: No description provided
- `-d`: No description provided
- `-j`: JSONPath expression to compare.  If not provided, run security checks.
- `-desc`: No description provided

## License
Copyright (c) ShadowStrikeHQ
