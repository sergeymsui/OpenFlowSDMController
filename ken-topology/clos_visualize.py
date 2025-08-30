import pickle
import networkx as nx
import matplotlib.pyplot as plt

# Загрузить граф
with open("clos_topograph.pickle", "rb") as f:
    G = pickle.load(f)

# Выделим типы узлов
node_colors = []
node_shapes = {
    "host": "o",
    "switch": "s",
}

# Разделим узлы по типу
hosts = [n for n, d in G.nodes(data=True) if d.get("type") == "host"]
switches = [n for n, d in G.nodes(data=True) if d.get("type") == "switch"]

# Позиции для отрисовки
pos = nx.spring_layout(G, seed=42)  # Можно заменить на shell_layout или planar_layout

# Отрисовка коммутаторов
nx.draw_networkx_nodes(G, pos, nodelist=switches, node_color='lightblue', node_shape='s', label='Switches', node_size=800)

# Отрисовка хостов
nx.draw_networkx_nodes(G, pos, nodelist=hosts, node_color='lightgreen', node_shape='o', label='Hosts', node_size=600)

# Рёбра
nx.draw_networkx_edges(G, pos, width=1.5)

# Подписи
nx.draw_networkx_labels(G, pos, font_size=8)

# Настройки
plt.title("Clos Topology Visualization")
plt.axis("off")
plt.legend()
plt.tight_layout()
plt.savefig("clos.png", format="PNG")
plt.close()
