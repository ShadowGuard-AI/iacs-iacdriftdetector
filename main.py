#!/usr/bin/env python3

import argparse
import logging
import sys
import yaml
import json
from jsonpath_ng import jsonpath, parse
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class IaCDriftDetector:
    """
    A tool that compares deployed infrastructure state with IaC configuration to detect drift.
    """

    def __init__(self, iac_file, deployed_state_file):
        """
        Initializes the IaCDriftDetector.

        Args:
            iac_file (str): Path to the IaC configuration file.
            deployed_state_file (str): Path to the file containing the deployed infrastructure state.
        """
        self.iac_file = iac_file
        self.deployed_state_file = deployed_state_file
        self.iac_data = None
        self.deployed_state_data = None

    def load_data(self):
        """
        Loads IaC configuration and deployed state data from files.
        Supports YAML and JSON formats based on file extension.
        """
        try:
            # Load IaC data
            if self.iac_file.endswith(('.yaml', '.yml')):
                with open(self.iac_file, 'r') as f:
                    self.iac_data = yaml.safe_load(f)
            elif self.iac_file.endswith('.json'):
                with open(self.iac_file, 'r') as f:
                    self.iac_data = json.load(f)
            else:
                raise ValueError(f"Unsupported file format for IaC file: {self.iac_file}.  Supported formats: YAML, JSON.")

            # Load deployed state data
            if self.deployed_state_file.endswith(('.yaml', '.yml')):
                with open(self.deployed_state_file, 'r') as f:
                    self.deployed_state_data = yaml.safe_load(f)
            elif self.deployed_state_file.endswith('.json'):
                with open(self.deployed_state_file, 'r') as f:
                    self.deployed_state_data = json.load(f)
            else:
                 raise ValueError(f"Unsupported file format for deployed state file: {self.deployed_state_file}. Supported formats: YAML, JSON.")

        except FileNotFoundError as e:
            logging.error(f"File not found: {e}")
            raise
        except yaml.YAMLError as e:
            logging.error(f"Error parsing YAML file: {e}")
            raise
        except json.JSONDecodeError as e:
            logging.error(f"Error parsing JSON file: {e}")
            raise
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            raise

    def compare(self, jsonpath_expression, description=""):
        """
        Compares specific configurations between IaC and deployed state using JSONPath.

        Args:
            jsonpath_expression (str): A JSONPath expression to locate the configuration elements to compare.
            description (str): A descriptive text for logging purposes.

        Returns:
            bool: True if drift is detected, False otherwise.
        """
        try:
            jsonpath_expr = parse(jsonpath_expression)

            iac_results = [match.value for match in jsonpath_expr.find(self.iac_data)]
            deployed_results = [match.value for match in jsonpath_expr.find(self.deployed_state_data)]


            if not iac_results:
                logging.warning(f"JSONPath expression '{jsonpath_expression}' returned no results in IaC configuration.")
                return False

            if not deployed_results:
                logging.warning(f"JSONPath expression '{jsonpath_expression}' returned no results in deployed state.")
                return False

            if iac_results != deployed_results:
                logging.warning(f"Drift detected for: {description} (JSONPath: {jsonpath_expression})")
                logging.warning(f"  IaC Configuration: {iac_results}")
                logging.warning(f"  Deployed State: {deployed_results}")
                return True
            else:
                logging.info(f"No drift detected for: {description} (JSONPath: {jsonpath_expression})")
                return False

        except Exception as e:
            logging.error(f"Error during comparison for JSONPath '{jsonpath_expression}': {e}")
            return False

    def run_security_checks(self):
        """
        Performs security-related checks by comparing specific configurations.
        Example checks are included; customize as needed.
        """
        logging.info("Running security checks...")

        # Example 1: Check for public access to a storage bucket
        self.compare("$.resource.aws_s3_bucket.acl", "S3 Bucket ACL",)

        # Example 2: Check for open security groups
        self.compare("$.resource.aws_security_group.ingress[*].cidr_blocks", "Security Group Ingress CIDR Blocks")

        # Example 3: Ensure encryption is enabled for databases
        self.compare("$.resource.aws_db_instance.storage_encrypted", "Database Storage Encryption Status")

        logging.info("Security checks completed.")


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(description="Detects configuration drift between IaC and deployed infrastructure.")

    parser.add_argument("-i", "--iac-file", required=True, help="Path to the IaC configuration file (YAML or JSON).")
    parser.add_argument("-d", "--deployed-state-file", required=True, help="Path to the file containing the deployed infrastructure state (YAML or JSON).")
    parser.add_argument("-j", "--jsonpath",  help="JSONPath expression to compare.  If not provided, run security checks.")
    parser.add_argument("-desc", "--description", help="Description of the comparison (used with --jsonpath).")


    return parser


def main():
    """
    Main function to execute the IaC Drift Detector.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Input validation
    if not os.path.exists(args.iac_file):
        logging.error(f"IaC file not found: {args.iac_file}")
        sys.exit(1)

    if not os.path.exists(args.deployed_state_file):
        logging.error(f"Deployed state file not found: {args.deployed_state_file}")
        sys.exit(1)

    detector = IaCDriftDetector(args.iac_file, args.deployed_state_file)

    try:
        detector.load_data()

        if args.jsonpath:
            if not args.description:
                logging.error("Description is required when using --jsonpath.")
                sys.exit(1)
            detector.compare(args.jsonpath, args.description)
        else:
            detector.run_security_checks()

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()