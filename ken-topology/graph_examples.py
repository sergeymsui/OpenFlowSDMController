import networkx as nx
import pickle
import matplotlib.pyplot as plt

topo_name = "vl2_topograph.pickle"

if __name__ == "__main__":
    graph = pickle.load(open(topo_name, "rb"))
    nx.draw(graph, with_labels=True, node_color="lightblue", edge_color="gray")
    plt.savefig("graph.png", format="PNG")
    plt.close()

    dpid = 2
    topo = pickle.load(open(topo_name, "rb"))

    for switch_name, _ in [
            (name, params)
            for name, params in topo.nodes(data=True)
            if "type" in params
            and params["type"] == "switch"
            and params["dpid"] == dpid
        ]:
            for host_name, host_params in [
                (name, params)
                for name, params in topo.nodes(data=True)
                if "type" in params and params["type"] == "host"
            ]:
                shortest_path = list()
                try:
                    shortest_path = [
                        node
                        for node in nx.shortest_path(
                            topo, source=host_name, target=switch_name
                        )
                    ]
                except nx.exception.NetworkXNoPath:
                    continue
                except nx.exception.NodeNotFound:
                    continue

                print(
                    f"[MSG] switch_name: {switch_name} host_name: {host_name} shortest_path: {shortest_path}"
                )
