from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import os

# Get credentials from environment variables for security
es_username = os.getenv('ELASTIC_USERNAME', 'elastic')
es_password = os.getenv('ELASTIC_PASSWORD', 'changeme')

# Elasticsearch connection details with basic authentication
es = Elasticsearch(
    ['http://192.168.1.74:9200'],
    basic_auth=(es_username, es_password)
)

# Index where alerts are stored
alerts_index = '.internal.alerts-security.alerts-default-000001'

# Query to fetch alerts from the last 24 hours
def fetch_alerts():
    now = datetime.utcnow()
    past_24_hours = now - timedelta(hours=24)

    query = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": past_24_hours,
                    "lte": now
                }
            }
        }
    }

    response = es.search(index=alerts_index, body=query)
    return response['hits']['hits']

# Prepare actionable info for analyst
def prepare_report(alerts):
    report = "Alert Report:\n\n"
    for alert in alerts:
        alert_info = alert['_source']
        report += f"Alert ID: {alert['_id']}\n"
        report += f"Timestamp: {alert_info['@timestamp']}\n"
        report += f"Rule Name: {alert_info.get('rule', {}).get('name', 'N/A')}\n"
        report += f"Event Category: {alert_info.get('event', {}).get('category', 'N/A')}\n"
        report += f"Event Action: {alert_info.get('event', {}).get('action', 'N/A')}\n"
        report += f"Host Name: {alert_info.get('host', {}).get('name', 'N/A')}\n"
        report += f"User Name: {alert_info.get('user', {}).get('name', 'N/A')}\n"
        report += f"Process Name: {alert_info.get('process', {}).get('name', 'N/A')}\n"
        report += f"Source IP: {alert_info.get('source', {}).get('ip', 'N/A')}\n"
        report += f"Destination IP: {alert_info.get('destination', {}).get('ip', 'N/A')}\n"
        report += f"Alert Details: {alert_info.get('message', 'No message available')}\n"
        report += "-"*40 + "\n"
    return report

# Main function
if __name__ == "__main__":
    alerts = fetch_alerts()
    report = prepare_report(alerts)
    print(report)