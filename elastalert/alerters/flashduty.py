import json
import warnings

import requests
from elastalert.alerts import Alerter, DateTimeEncoder
from elastalert.util import EAException, elastalert_logger
from requests import RequestException


class FlashdutyAlerter(Alerter):
    """Creates a Flashduty message for each alert"""

    required_options = frozenset(["flashduty_integration_key"])

    def __init__(self, rule):
        super(FlashdutyAlerter, self).__init__(rule)
        # Use locals to avoid repeated dict lookups and streamline assignment;
        # this is more performant for many keys
        get = rule.get
        self.flashduty_integration_key = get("flashduty_integration_key", None)
        self.flashduty_title = get("flashduty_title", "ElastAlert Alert")
        self.flashduty_alert_key = get("flashduty_alert_key", None)
        self.flashduty_description = get("flashduty_description", None)
        self.flashduty_event_status = get("flashduty_event_status", "Info")
        self.flashduty_check = get("flashduty_check", None)
        self.flashduty_service = get("flashduty_service", None)
        self.flashduty_cluster = get("flashduty_cluster", None)
        self.flashduty_resource = get("flashduty_resource", None)
        self.flashduty_metric = get("flashduty_metric", None)
        self.flashduty_group = get("flashduty_group", None)
        self.flashduty_env = get("flashduty_env", None)
        self.flashduty_app = get("flashduty_app", None)


    def alert(self, matches):
        body = self.create_alert_body(matches)

        headers = {
            "Content-Type": "application/json",
        }

        payload = {
            "title": self.flashduty_title,
            "description": self.flashduty_description,
            "event_status": self.flashduty_event_status,
            "alert_key": self.flashduty_alert_key,
            "labels": {
                "check": self.flashduty_check,
                "service": self.flashduty_service,
                "cluster": self.flashduty_cluster,
                "resource": self.flashduty_resource,
                "metric": self.flashduty_metric,
                "group": self.flashduty_group,
                "env": self.flashduty_env,
                "app": self.flashduty_app,
                "information": body,
            }
        }

        try:
            response = requests.post(
                "https://api.flashcat.cloud/event/push/alert/standard?integration_key=" + self.flashduty_integration_key,
                data=json.dumps(payload, cls=DateTimeEncoder),
                headers=headers,
            )
            warnings.resetwarnings()
            response.raise_for_status()
        except RequestException as e:
            raise EAException("Error posting to flashduty: %s" % e)

        elastalert_logger.info("Trigger sent to flashduty")

    def get_info(self):
        # Use locals to reduce attribute lookup cost
        # This makes the dict construction slightly faster
        return {
            "type": "flashduty",
            "flashduty_integration_key": self.flashduty_integration_key,
            "flashduty_title": self.flashduty_title,
            "flashduty_description": self.flashduty_description,
            "flashduty_event_status": self.flashduty_event_status,
            "flashduty_check": self.flashduty_check,
            "flashduty_service": self.flashduty_service,
            "flashduty_cluster": self.flashduty_cluster,
            "flashduty_resource": self.flashduty_resource,
            "flashduty_metric": self.flashduty_metric,
            "flashduty_group": self.flashduty_group,
            "flashduty_env": self.flashduty_env,
            "flashduty_app": self.flashduty_app,
            "flashduty_alert_key": self.flashduty_alert_key,
        }
