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
            bool: True if drift is detected, False otherwise. A path
            present on one side only counts as drift. Parse and
            comparison errors raise instead of returning False, and an
            expression that matches nothing on either side raises
            ValueError, because no comparison was performed.
        """
        jsonpath_expr = parse(jsonpath_expression)

        iac_results = [match.value for match in jsonpath_expr.find(self.iac_data)]
        deployed_results = [match.value for match in jsonpath_expr.find(self.deployed_state_data)]

        if not iac_results and not deployed_results:
            raise ValueError(
                f"JSONPath expression '{jsonpath_expression}' returned no results on either side; "
                "no comparison was performed."
            )

        if not iac_results or not deployed_results:
            missing_side = "IaC configuration" if not iac_results else "deployed state"
            present_results = deployed_results if not iac_results else iac_results
            logging.warning(f"Drift detected for: {description} (JSONPath: {jsonpath_expression})")
            logging.warning(f"  The expression returned no results in {missing_side}.")
            logging.warning(f"  Present side value: {present_results}")
            return True

        # The two match lists are compared as lists, order included. The same
        # values found in a different document order on the two sides are
        # reported as drift, even though as sets they are identical.
        if iac_results != deployed_results:
            logging.warning(f"Drift detected for: {description} (JSONPath: {jsonpath_expression})")
            logging.warning(f"  IaC Configuration: {iac_results}")
            logging.warning(f"  Deployed State: {deployed_results}")
            return True
        else:
            logging.info(f"No drift detected for: {description} (JSONPath: {jsonpath_expression})")
            return False

    def run_security_checks(self):
        """
        Performs security-related checks by comparing specific configurations.
        The default expressions carry a wildcard label segment, so they
        match labelled resources (resource.aws_s3_bucket.<label>.acl and
        its siblings) as well as the unlabelled shape.

        Returns:
            bool: True if any check reports drift. Raises ValueError
            when a default check matches nothing on either side, so a
            run that compared nothing never completes clean.
        """
        logging.info("Running security checks...")

        # The default checks are three fixed AWS paths in the parsed shape an
        # HCL loader would produce. The files this tool loads are YAML or JSON,
        # so the state file has to be written in that same nested shape by
        # hand; a real Terraform state file does not look like this.
        checks = [
            (["$.resource.aws_s3_bucket.*.acl", "$.resource.aws_s3_bucket.acl"], "S3 Bucket ACL"),
            (["$.resource.aws_security_group.*.ingress[*].cidr_blocks",
              "$.resource.aws_security_group.ingress[*].cidr_blocks"], "Security Group Ingress CIDR Blocks"),
            (["$.resource.aws_db_instance.*.storage_encrypted",
              "$.resource.aws_db_instance.storage_encrypted"], "Database Storage Encryption Status"),
        ]

        drift_found = False
        unmatched = []
        for expressions, description in checks:
            try:
                if self._compare_any(expressions, description):
                    drift_found = True
            except ValueError:
                unmatched.append(expressions[0])

        # Unmatched checks are collected across all three defaults and raised
        # together at the end. Because the raise replaces the return, a run
        # where one check found real drift and another matched nothing exits
        # through the error path in main, and the drift verdict itself is only
        # in the warning lines above.
        if unmatched:
            raise ValueError(
                "Default security checks matched nothing on either side, so no comparison was "
                f"performed for: {', '.join(unmatched)}"
            )

        logging.info("Security checks completed.")
        return drift_found

    def _compare_any(self, expressions, description=""):
        """
        Tries each expression in order and returns the verdict of the
        first one that matches on at least one side. Raises ValueError
        when none of them matched anything on either side.
        """
        for expression in expressions:
            try:
                # The first expression that matches anything on either side decides
                # the check. An expression that matches on one side only returns drift
                # at once, and the fallback expression is never tried, even though it
                # might have matched both sides cleanly.
                return self.compare(expression, description)
            except ValueError:
                continue
        raise ValueError(
            f"None of the expressions {expressions} returned results on either side; "
            "no comparison was performed."
        )


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
            drift_found = detector.compare(args.jsonpath, args.description)
        else:
            drift_found = detector.run_security_checks()

        if drift_found:
            logging.warning("Drift detected; exiting with code 1.")
            sys.exit(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()