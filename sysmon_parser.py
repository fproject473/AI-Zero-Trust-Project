import pandas as pd
import xml.etree.ElementTree as ET
from datetime import datetime
import re
import csv

def parse_sysmon_xml(xml_file_path):
    """
    Parse Sysmon XML export file and extract key security events
    """
    try:
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        events = []

        # Namespace for Windows Event Log XML
        ns = {'event': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        for event in root.findall('.//event:Event', ns):
            event_data = {}

            # Extract System data
            system = event.find('event:System', ns)
            if system is not None:
                event_id = system.find('event:EventID', ns)
                time_created = system.find('event:TimeCreated', ns)

                event_data['EventID'] = event_id.text if event_id is not None else ''
                event_data['Timestamp'] = time_created.get('SystemTime') if time_created is not None else ''

            # Extract EventData
            event_data_elem = event.find('event:EventData', ns)
            if event_data_elem is not None:
                for data in event_data_elem.findall('event:Data', ns):
                    name = data.get('Name')
                    value = data.text if data.text else ''
                    event_data[name] = value

            events.append(event_data)

        return pd.DataFrame(events)

    except Exception as e:
        print(f"Error parsing XML: {e}")
        return None

def parse_sysmon_text_export(log_file_path):
    """
    Parse Sysmon text format logs (from Event Viewer export)
    """
    events = []
    current_event = {}

    try:
        with open(log_file_path, 'r', encoding='utf-16-le') as f:
            for line in f:
                line = line.strip()

                # Check for event boundaries
                if 'Event ID:' in line:
                    if current_event:
                        events.append(current_event)
