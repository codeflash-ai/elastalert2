import os
import yaml
from datetime import datetime
from elasticsearch.exceptions import TransportError
from elastalert.alerts import Alerter
from elastalert.util import lookup_es_key, EAException, elastalert_logger, elasticsearch_client

class IndexerAlerter(Alerter):
    """
    Use matched data to create alerts on Opensearch/Elasticsearch
    """
    required_options = frozenset(['indexer_alert_config'])

    def lookup_field(self, match: dict, field_name: str, default):
        # Try fast-path lookup in match first, only call lookup_es_key if needed
        result = None
        if isinstance(match, dict) and field_name in match:
            result = match[field_name]
        else:
            result = lookup_es_key(match, field_name)
        if result is None:
            result = self.rule.get(field_name, default)
        return result

    def get_query(self,body_request_raw):
        original = body_request_raw[0]
        for orig in original.values():
            for query_string in orig.values():
                query = query_string
        return query['query']

    def lookup_list_fields(self, original_fields_raw: list, match: dict):
        """Optimized for reduced redundant lookups: minimizing method calls and lookups."""
        original_fields = {}
        append_field = original_fields.__setitem__
        for field in original_fields_raw:
            get_field_value = field.get('value')
            if get_field_value:
                if isinstance(get_field_value, str):
                    if get_field_value == 'filter':
                        body_request_raw = self.rule.get(get_field_value)
                        value = self.get_query(body_request_raw)
                    else:
                        # Try fast-path lookup to avoid repeated deep search
                        if isinstance(match, dict) and get_field_value in match:
                            value = match[get_field_value]
                        else:
                            value = lookup_es_key(match, get_field_value)
                        if value is None:
                            value = self.rule.get(get_field_value, get_field_value)
                else:
                    value = get_field_value
                append_field(field['name'], value)
            else:
                for k, v in field.items():
                    append_field(k, self.lookup_list_fields(v, match))
        return original_fields

    def event_orig_fields(self, original_fields_raw, match: dict):
        # Fast-path: check for dict first, so we only invoke lookup_field
        if isinstance(original_fields_raw, str):
            value = self.lookup_field(match, original_fields_raw, original_fields_raw)
        elif isinstance(original_fields_raw, list):
            value = self.lookup_list_fields(original_fields_raw, match)
        else:
            value = original_fields_raw
        return value

    def make_nested_fields(self, data):
        nested_data = {}
        for key, value in data.items():
            keys = key.split(".")
            current_nested_data = nested_data
            for nested_key in keys[:-1]:
                current_nested_data = current_nested_data.setdefault(nested_key, {})
            current_nested_data[keys[-1]] = value
        return nested_data

    def flatten_dict(self, data, prefix='', sep='.'):
        nd = {}
        for k, v in data.items():
            if isinstance(v, dict):
                nd.update(self.flatten_dict(v, f'{prefix}{k}{sep}'))
            else:
                nd[f'{prefix}{k}'] = v
        return nd

    def remove_matching_pairs(self, input_dict):
        return {key: value for key, value in input_dict.items() if key != value}

    def alert(self, matches):
        alert_config = {
            '@timestamp': datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        }
        alert_config.update(self.rule.get('indexer_alert_config', {}))

        if len(matches) > 0:
            alert_config = self.flatten_dict(alert_config)
            for event_orig in alert_config:
                alert_config[event_orig] = self.event_orig_fields(alert_config[event_orig],matches[0])
        alert_config = self.remove_matching_pairs(self.flatten_dict(alert_config))
        alert_config = self.make_nested_fields(alert_config)


        # POST the alert to SIEM
        try:
            data = self.rule.get('indexer_connection', '')
            if not data:
                if os.path.isfile(self.rule.get('indexer_config', '')):
                    filename = self.rule.get('indexer_config', '')
                else:
                    filename = ''

                if filename:
                    with open(filename) as config_file:
                        data = yaml.load(config_file, Loader=yaml.FullLoader)
            elasticsearch_client(data).index(index = data.get('indexer_alerts_name'),
                                              body = alert_config,
                                              refresh = True)

        except TransportError as e:
            raise EAException(f"Error posting to SIEM: {e}")
        elastalert_logger.info("Alert sent to SIEM")

    def get_info(self):
        return {'type': 'indexer'}
