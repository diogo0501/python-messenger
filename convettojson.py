import csv
from pymisp import MISPObject, PyMISP, MISPEvent, MISPAttribute

def main(csv_file_path, misp_url, misp_key, misp_verifycert):
    misp = PyMISP(misp_url, misp_key, misp_verifycert)
    
    with open(csv_file_path, 'r', newline='', encoding='utf-8') as file:
        sample = file.read(1024)
        file.seek(0)
        delimiter = detect_delimiter(sample)
        
        reader = csv.DictReader(file, delimiter=delimiter)
        next(reader, None)  # Skip the header if it's present
        for row in reader:
            create_event(row, misp)

def detect_delimiter(sample):
    possible_delimiters = ['|', ';', ',']
    delimiter_counts = {delimiter: sample.count(delimiter) for delimiter in possible_delimiters}
    return max(delimiter_counts, key=delimiter_counts.get)


def create_event(attribute_data, misp_instance):
    event = MISPEvent()
    application = attribute_data.get('Id') or attribute_data.get('APP')  or attribute_data.get('\ufeffexternal_app_nam') or attribute_data.get('\ufeffApp') or attribute_data.get('Feed') or attribute_data.get('app') or 'Unknown Application'
    print(attribute_data)
    event.info = f"Vulnerability Report: {application}"
    event.distribution = 0
    risk = attribute_data.get('severity') or attribute_data.get('Risk Level') or 'Undefined'
    event.threat_level_id = map_severity_to_threat_level(risk)
    event.analysis = 0

    av_signature_object = MISPObject("av-signature")

    for key, value in attribute_data.items():
        if key is None:
            av_signature_object.add_attribute('none', value=value, type='text')
        elif key.lower() in ['url', 'link']:
            av_signature_object.add_attribute('url', value=value, type='url')
        elif key.lower() in ['ip', 'ip_address']:
            av_signature_object.add_attribute('ip', value=value, type='ip_address')
        else:
            av_signature_object.add_attribute(key, value=value, type='text')

    event.add_object(av_signature_object) 
    misp_instance.add_event(event)

def map_severity_to_threat_level(severity):
    mapping = {
        'Critical': 1,  
        'High': 1,
        'Medium': 2,
        'Low': 3,
        'Informational': 4,  
        'Undefined': 4
    }
    return mapping.get(severity, 4) 

if __name__ == '__main__':
    csv_file_path = './feed_modc_13.csv'
    misp_url = 'https://localhost:8443'
    misp_key = '5JHP0V1zEzA8caqJ6TOgNgjvSSh6d8nGdbraaDDf'
    misp_verifycert = False
    main(csv_file_path, misp_url, misp_key, misp_verifycert)
