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
                if i.get('object_relation') == 'Vulnerabilidades' or i.get('object_relation') == 'Vuln':
                    vul = i.get('value')
                elif i.get('object_relation') == 'Descrição' or i.get('object_relation') == 'Note':
                    desc = i.get('value')
            results.append({
                "vulnerability_type": vul,
                "description": desc,
                "App": app,
            })
    return results

# Função para criar uma tabela
def create_table(vulnerability_info):
    df = pd.DataFrame(vulnerability_info)

    fig, ax = plt.subplots(figsize=(10, len(df) * 0.5))  # Adjust height based on number of rows

    # Hide the axes
    ax.xaxis.set_visible(False)
    ax.yaxis.set_visible(False)
    ax.set_frame_on(False)

    # Create the table
    table = plt.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center', colColours=['#f1f1f2'] * len(df.columns))
    
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.auto_set_column_width(col=list(range(len(df.columns))))

    # Set row height
    table.scale(1, 1.2)

    # Style the table
    for (i, j), cell in table.get_celld().items():
        if i == 0:
            cell.set_fontsize(10)
            cell.set_text_props(weight='bold', color='white')
            cell.set_facecolor('#40466e')
        else:
            cell.set_facecolor('#f1f1f2')
        cell.set_edgecolor('#4d4d4d')

    plt.title('Vulnerability Report', fontsize=14, weight='bold')
    plt.subplots_adjust(left=0.1, right=0.9, top=0.9, bottom=0.1)  # Adjust layout to make more room for the table
    plt.show()

# Função para correlacionar vulnerabilidades
def correlate_vulnerabilities(vulnerability_info):
    correlation_map = {}
    for info in vulnerability_info:
        vul_type = info['vulnerability_type']
        desc = info['description']
        if vul_type in correlation_map:
            correlation_map[vul_type].append(desc)
        else:
            correlation_map[vul_type] = [desc]
    return correlation_map

def create_network_graph(correlation_map, filename):
    G = nx.Graph()

    # Adicionando nós e arestas ao grafo
    for vul_type, descriptions in correlation_map.items():
        G.add_node(vul_type, color='#1f78b4', size=300, label=vul_type)
        for desc in descriptions:
            G.add_node(desc, color='#33a02c', size=300, label=desc)
            G.add_edge(vul_type, desc, color='#b2df8a')

    # Gerando posições dos nós com um layout de mola
    pos = nx.spring_layout(G, k=0.75)
    nx.set_node_attributes(G, pos, 'pos')  # Definindo atributo de posição

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
    plt.title('Vulnerability Correlation Network', fontsize=20)

    # Definindo limites baseados em posições dos nós usando NumPy para cálculo correto
    all_pos = np.array(list(pos.values()))
    plt.xlim(np.min(all_pos[:, 0]) - 0.1, np.max(all_pos[:, 0]) + 0.1)
    plt.ylim(np.min(all_pos[:, 1]) - 0.1, np.max(all_pos[:, 1]) + 0.1)

    plt.savefig(filename, bbox_inches='tight')  # Salvando a figura
    plt.close()


value_to_search = "abd11"

vulnerability_info = fetch_vulnerability_info(value_to_search)

# Correlate vulnerabilities
correlation_map = correlate_vulnerabilities(vulnerability_info)


# Chamar a função com o mapa de correlação e o caminho do arquivo para salvar
create_network_graph(correlation_map, './abd11Corr.png')

# Create and display the table
create_table(vulnerability_info)

