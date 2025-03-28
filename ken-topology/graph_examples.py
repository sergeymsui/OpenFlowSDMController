import networkx as nx
import pickle
import matplotlib.pyplot as plt


if __name__ == "__main__":
    graph = pickle.load(open("filename.pickle", "rb"))

    # Рисуем граф
    nx.draw(graph, with_labels=True, node_color='lightblue', edge_color='gray')

    # Сохраняем в PNG
    plt.savefig("graph.png", format="PNG")
    plt.close()  # Закрываем рисунок, чтобы не показывался в выводе

    edges = [ (u, v, params) for (u, v, params) in graph.edges(data=True)
             if v=="s2"]
    print(edges)