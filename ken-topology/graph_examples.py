import networkx as nx
import pickle
import matplotlib.pyplot as plt

from utils import generate_ilp_flows

if __name__ == "__main__":
    graph = pickle.load(open("topograph.pickle", "rb"))
    # nx.draw(graph, with_labels=True, node_color='lightblue', edge_color='gray')
    # plt.savefig("graph.png", format="PNG")
    # plt.close()

    # edges = [ (u, v, params) for (u, v, params) in graph.edges(data=True)
    #          if v=="s2"]
    # print(edges)

    targets_list = []
    nflows = 2

    for src, dst in [("h1", "h3"), ("h2", "h4")] * nflows:
        targets_list.append((src, dst))
        targets_list.append((dst, src))

    flows = generate_ilp_flows(graph, targets_list)

    for idx, path in flows.items():
        print(idx, path)

    # for source, target, ports in [
    #     (source, target, ports)
    #     for (source, target, ports) in graph.edges(data=True)
    #     if source == "s5" and target == "h3"
    # ]:
    #     print("+", source, target, ports)

    # for switch_name, switch_params in [
    #     (name, params)
    #     for name, params in graph.nodes(data=True)
    #     if "type" in params and params["type"] == "switch" and name == "s5"
    # ]:
    #     print("+", switch_name, switch_params)
    #     pass
