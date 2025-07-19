import argparse
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

import schedule
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


class LogEventCorrelator:
    """
    Correlates log events based on defined patterns to trigger alerts or actions.
    """

    def __init__(self, config: Dict):
        """
        Initializes the LogEventCorrelator with configuration parameters.

        Args:
            config (Dict): A dictionary containing configuration options.
                           Must include:
                               - log_file (str): Path to the log file.
                               - patterns (List[Dict]): List of patterns to match. Each pattern
                                 should have 'name' (str), 'regex' (str), 'aggregation_window' (int),
                                 'threshold' (int), 'alert_destination' (str)
                               - aggregation_interval (int): Interval in seconds to check for matches.
        """
        self.log_file = config.get("log_file")
        self.patterns = config.get("patterns")
        self.aggregation_interval = config.get("aggregation_interval", 60)
        self.alerts_fired = set()
        self.event_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )  # {pattern_name: {timestamp_window: count}}
        self.last_processed_line = 0

        if not self.log_file:
            raise ValueError("log_file must be specified in the configuration.")

        if not self.patterns:
            raise ValueError("patterns must be specified in the configuration.")

        for pattern in self.patterns:
            if not all(
                key in pattern
                for key in ["name", "regex", "aggregation_window", "threshold", "alert_destination"]
            ):
                raise ValueError(
                    "Each pattern must include 'name', 'regex', 'aggregation_window', 'threshold', and 'alert_destination'."
                )
            try:
                re.compile(pattern["regex"])  # Test if regex is valid
            except re.error as e:
                raise ValueError(
                    f"Invalid regex '{pattern['regex']}' for pattern '{pattern['name']}': {e}"
                )

    def process_logs(self):
        """
        Processes the log file, matches patterns, and triggers alerts.
        """
        try:
            with open(self.log_file, "r") as f:
                # Seek to the last processed line
                for _ in range(self.last_processed_line):
                    next(f, None)

                for line in f:
                    line = line.strip()
                    self.last_processed_line += 1  # Increment the counter.

                    if not line:
                        continue  # Skip empty lines

                    timestamp = datetime.now()  # Current timestamp
                    for pattern in self.patterns:
                        if re.search(pattern["regex"], line):
                            logging.debug(
                                f"Matched pattern '{pattern['name']}' in line: {line}"
                            )
                            window_key = self._calculate_window_key(
                                timestamp, pattern["aggregation_window"]
                            )
                            self.event_counts[pattern["name"]][window_key] += 1
                            self._check_threshold_and_alert(pattern, window_key)

        except FileNotFoundError:
            logging.error(f"Log file not found: {self.log_file}")
        except Exception as e:
            logging.error(f"Error processing logs: {e}")

    def _calculate_window_key(self, timestamp: datetime, aggregation_window: int) -> str:
        """
        Calculates the window key based on the timestamp and aggregation window.

        Args:
            timestamp (datetime): The timestamp of the event.
            aggregation_window (int): The aggregation window in seconds.

        Returns:
            str: The window key.
        """
        window_start = timestamp - timedelta(
            seconds=timestamp.second % aggregation_window,
            microseconds=timestamp.microsecond,
        )
        return window_start.isoformat()

    def _check_threshold_and_alert(self, pattern: Dict, window_key: str):
        """
        Checks if the threshold is exceeded and triggers an alert.

        Args:
            pattern (Dict): The pattern definition.
            window_key (str): The window key.
        """
        pattern_name = pattern["name"]
        threshold = pattern["threshold"]
        alert_destination = pattern["alert_destination"]
        count = self.event_counts[pattern_name][window_key]

        if count >= threshold:
            alert_id = f"{pattern_name}-{window_key}"
            if alert_id not in self.alerts_fired:
                logging.warning(
                    f"Threshold exceeded for pattern '{pattern_name}' in window '{window_key}': Count = {count}, Threshold = {threshold}. Alerting {alert_destination}"
                )
                self._trigger_alert(alert_destination, pattern_name, count, window_key)
                self.alerts_fired.add(alert_id)
            else:
                logging.debug(
                    f"Alert already fired for {pattern_name} in window {window_key}"
                )

    def _trigger_alert(
        self, alert_destination: str, pattern_name: str, count: int, window_key: str
    ):
        """
        Triggers an alert based on the alert destination.  Can be extended to more destinations
        Args:
            alert_destination (str): The alert destination (e.g., email address, script path).
            pattern_name (str): The name of the pattern that triggered the alert.
            count (int): The count of events that triggered the alert.
            window_key (str): The time window of the alert.
        """
        try:
            if alert_destination.startswith("script:"):
                script_path = alert_destination[len("script:") :]
                if not os.path.exists(script_path):
                    logging.error(f"Script not found: {script_path}")
                    return

                # Security note: Be VERY careful about running external scripts.
                # Ensure scripts are properly vetted and sandboxed if possible.
                # Consider using a more robust and secure method for triggering actions.
                command = [
                    script_path,
                    "--pattern",
                    pattern_name,
                    "--count",
                    str(count),
                    "--window",
                    window_key,
                ]
                logging.info(f"Executing alert script: {command}")
                os.system(" ".join(command))  # Insecure; use subprocess.run with proper escaping.
            else:
                # Placeholder for other alert mechanisms (e.g., email, API calls)
                logging.info(
                    f"Simulating alert to {alert_destination} for pattern '{pattern_name}': Count = {count}, Window = {window_key}"
                )
        except Exception as e:
            logging.error(f"Error triggering alert: {e}")

    def cleanup_old_counts(self):
        """
        Cleans up old event counts to prevent memory usage from growing indefinitely.
        """
        current_time = datetime.now()
        for pattern_name, window_counts in self.event_counts.items():
            for window_key in list(window_counts.keys()):  # Iterate over a copy of keys
                try:
                    window_start = datetime.fromisoformat(window_key)
                    aggregation_window = next(
                        (
                            p["aggregation_window"]
                            for p in self.patterns
                            if p["name"] == pattern_name
                        ),
                        None,
                    )
                    if aggregation_window is None:
                        logging.warning(
                            f"Aggregation window not found for pattern '{pattern_name}', skipping cleanup."
                        )
                        continue

                    if current_time - window_start > timedelta(
                        seconds=3 * aggregation_window
                    ):  # Keep data for 3x window duration
                        del window_counts[window_key]
                        logging.debug(
                            f"Removed old count for pattern '{pattern_name}' in window '{window_key}'"
                        )
                except ValueError:
                    logging.warning(
                        f"Invalid window key format: {window_key}. Skipping cleanup."
                    )
                except Exception as e:
                    logging.error(f"Error cleaning up old counts: {e}")


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: The argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Correlates log events based on defined patterns to trigger alerts."
    )
    parser.add_argument(
        "--config",
        "-c",
        type=str,
        default="config.json",
        help="Path to the configuration file (JSON).",
    )
    parser.add_argument(
        "--oneshot",
        action="store_true",
        help="Run the correlation once and exit. Useful for testing.",
    )
    return parser


def load_config(config_file: str) -> Dict:
    """
    Loads the configuration from a JSON file.

    Args:
        config_file (str): The path to the configuration file.

    Returns:
        Dict: The configuration dictionary.
    """
    import json

    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        raise
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in configuration file: {config_file}")
        raise
    except Exception as e:
        logging.error(f"Error loading configuration: {e}")
        raise


def main():
    """
    Main function to run the log event correlator.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        correlator = LogEventCorrelator(config)

        def job():
            correlator.process_logs()
            correlator.cleanup_old_counts()

        aggregation_interval = config.get("aggregation_interval", 60)

        schedule.every(aggregation_interval).seconds.do(job)

        if args.oneshot:
            job()  # Run once
            logging.info("Log correlation completed in oneshot mode.")
        else:
            logging.info(
                f"Log correlation started. Checking every {aggregation_interval} seconds."
            )
            while True:
                schedule.run_pending()
                time.sleep(1)

    except Exception as e:
        logging.error(f"An error occurred: {e}")


if __name__ == "__main__":
    main()


# Example config.json:
# {
#   "log_file": "sample.log",
#   "patterns": [
#     {
#       "name": "error_pattern",
#       "regex": "ERROR",
#       "aggregation_window": 60,
#       "threshold": 3,
#       "alert_destination": "script:./alert_script.sh"
#     },
#     {
#       "name": "login_failure",
#       "regex": "Failed login attempt",
#       "aggregation_window": 300,
#       "threshold": 5,
#       "alert_destination": "admin@example.com"
#     }
#   ],
#   "aggregation_interval": 30
# }

# Example alert_script.sh:
# #!/bin/bash
# echo "Alert triggered: Pattern=$1 Count=$2 Window=$3" >> alert.log