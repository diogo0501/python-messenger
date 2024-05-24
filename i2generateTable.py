import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import requests

misp_verifycert = False

# Definir URL e cabeçalhos da API
misp_url = "https://localhost:8443/attributes/restSearch"
headers = {
    "Authorization": "5JHP0V1zEzA8caqJ6TOgNgjvSSh6d8nGdbraaDDf",
    "Accept": "application/json",
    "Content-type": "application/json"
}

# Função para buscar IDs dos eventos que possuem o atributo "abp00"
def fetch_event_ids_with_attribute(attribute_value):
    search_payload = {
        "value": attribute_value
    }
    response = requests.post(misp_url, headers=headers, json=search_payload, verify=False)  # Desabilitar verificação SSL
    return response.json()

# Função para buscar detalhes de um evento por ID
def fetch_event_details(event_id):
    event_url = f"https://localhost:8443/events/view/{event_id}"
    response = requests.get(event_url, headers=headers, verify=False)  # Desabilitar verificação SSL
    return response.json()

# Função principal para buscar e extrair informações das vulnerabilidades
def fetch_vulnerability_info(attribute_value):
    event_ids = fetch_event_ids_with_attribute(attribute_value)
    resp = event_ids.get('response').get('Attribute')
    results = []
    for event in resp:
        event_id = event.get('event_id')
        event_details = fetch_event_details(event_id)
        event_info = event_details.get('Event', {}).get('Object')
        app = attribute_value
        for attribute in event_info:
            item = attribute.get('Attribute')  
            vul = ''
            desc = ''
            for i in item:
                if i.get('object_relation') ==  'Vulnerability Type' or i.get('object_relation') ==  'Vulnerabilidades' or i.get('object_relation') ==  'vulnerability' or i.get('object_relation') ==  'Vulnerability' or i.get('object_relation') == 'Vuln' or i.get('object_relation') == 'vulnerability_type':
                    vul = i.get('value')
                elif i.get('object_relation') == 'Descrição' or  i.get('object_relation') == 'exploitation' or i.get('object_relation') == 'line' or i.get('object_relation') == 'Line of Code' or i.get('object_relation') == 'Description' or i.get('object_relation') == 'Input/Description' or i.get('object_relation') == 'description' or i.get('object_relation') == 'Note':
                    desc = i.get('value')
            results.append({
                "vulnerability_type": vul,
                "description": desc,
                "App": app,
            })
    return results


def save_vulnerabilities_to_csv(vulnerability_info_list, file_name):
    # Combine all DataFrames into one
    combined_df = pd.concat(vulnerability_info_list, ignore_index=True)

    # Save the DataFrame to a CSV file
    combined_df.to_csv(file_name, index=False)
    print(f"Data saved to {file_name}")


def correlate_vulnerabilities(vulnerability_info):
    correlation_map = {}
    for info in vulnerability_info.itertuples():
        vul_type = getattr(info, 'vulnerability_type')
        desc = getattr(info, 'description')
        if vul_type in correlation_map:
            correlation_map[vul_type].append(desc)
        else:
            correlation_map[vul_type] = [desc]
    return correlation_map

def create_network_graph(correlation_map, filename):
    G = nx.Graph()

    # Adicionando nós e arestas ao grafo
    for vul_type, descriptions in correlation_map.items():
        G.add_node(vul_type, color='#1f78b4', size=250, label=vul_type)
        for desc in descriptions:
            G.add_node(desc, color='#33a02c', size=250, label=desc)
            G.add_edge(vul_type, desc, color='#b2df8a')

    pos = nx.spring_layout(G, k=4500)  
    nx.set_node_attributes(G, pos, 'pos') 

    plt.figure(figsize=(16, 16))
    nx.draw(G, pos, with_labels=False, node_color=[G.nodes[n]['color'] for n in G.nodes],
            node_size=[G.nodes[n]['size'] for n in G.nodes], edge_color=[G[u][v]['color'] for u, v in G.edges])

    # Adicionando texto em cima dos nós
    for node, (x, y) in pos.items():
        plt.text(x, y, s=node, fontsize=8, ha='center', va='center', bbox=dict(facecolor='white', edgecolor='none', alpha=0.5))

    legend_labels = {'#1f78b4': 'Vulnerability Type', '#33a02c': 'Description'}
    for color, label in legend_labels.items():
        plt.scatter([], [], c=color, label=label)
    plt.legend(loc='best', frameon=False)
    plt.title('Vulnerability Correlation Network', fontsize=8)

    # Definindo limites baseados em posições dos nós usando NumPy para cálculo correto
    all_pos = np.array(list(pos.values()))
    plt.xlim(np.min(all_pos[:, 0]) - 0.1, np.max(all_pos[:, 0]) + 0.1)
    plt.ylim(np.min(all_pos[:, 1]) - 0.1, np.max(all_pos[:, 1]) + 0.1)

    plt.savefig(filename, bbox_inches='tight')  # Salvando a figura
    plt.close()

vulnerability_info = fetch_vulnerability_info("i2")
vulnerability_info2 = fetch_vulnerability_info("Vulnerable Web Application")
vulnerability_info3 = fetch_vulnerability_info("Vulnerable-Web-Application")

vulnerability_info_list = [pd.DataFrame(vulnerability_info), pd.DataFrame(vulnerability_info2), pd.DataFrame(vulnerability_info3)]
all_vulnerabilities = pd.concat(vulnerability_info_list)
all_vulnerabilities.to_csv("vulnerability_report.csv", index=False)

correlation_map = correlate_vulnerabilities(all_vulnerabilities)
create_network_graph(correlation_map, "vulnerability_network.png")