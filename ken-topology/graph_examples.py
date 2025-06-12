import networkx as nx
import pickle
import matplotlib.pyplot as plt


if __name__ == "__main__":
    graph = pickle.load(open("vl2_topograph.pickle", "rb"))
    nx.draw(graph, with_labels=True, node_color="lightblue", edge_color="gray")
    plt.savefig("graph.png", format="PNG")
    plt.close()
