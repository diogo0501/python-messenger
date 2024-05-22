import pandas as pd
import json
from datetime import datetime

def process_csv_to_misp_json(csv_file, json_file):
    df = pd.read_csv(csv_file, sep=None, engine='python')  
    misp_event = {
        "Event": {
            "info": "Imported vulnerability data",
            "date": datetime.now().strftime('%Y-%m-%d'),
            "threat_level_id": "3",
            "analysis": "0", 
            "Attribute": []
        }
    }

    for _, row in df.iterrows():
        if 'Vulnerability' in df.columns:
            attribute = {
                "type": "vulnerability",
                "category": "External analysis",
                "to_ids": False,
                "value": row.get('Vulnerability', ''),
                "comment": f"CWE: {row.get('CWE', '')}, Severity: {row.get('Severity', '')}"
            }
            misp_event["Event"]["Attribute"].append(attribute)

        if 'URL' in df.columns and row.get('URL', ''):
            misp_event["Event"]["Attribute"].append({
                "type": "url",
                "category": "External analysis",
                "value": row['URL'],
                "to_ids": False
            })

        # Add more conditions based on other columns

    # Save the structured event to a JSON file
    with open(json_file, 'w') as f:
        json.dump(misp_event, f, indent=4)

# Example usage for multiple files
file_paths = ["path_to_file1.csv", "path_to_file2.csv", ...]  # List all your file paths
for file_path in file_paths:
    json_path = file_path.replace('.csv', '.json')
    process_csv_to_misp_json(file_path, json_path)
