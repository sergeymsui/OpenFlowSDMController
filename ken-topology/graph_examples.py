import networkx as nx
import pickle

if __name__ == "__main__":
    graph = pickle.load(open("filename.pickle", "rb"))

    switches = ["h1"] + [
        n for n, v in graph.nodes(data=True) if "type" in v and v["type"] == "switch"
    ]

    # edge = [
    #     (source, target, ports)
    #     for (source, target, ports) in graph.edges(data=True)
    #     if source == "h1" and target == "s1"
    # ]
    # print(edge)

    for host_name, host_params in [ (name, params) for name, params in graph.nodes(data=True) if "type" in params and params["type"] == "host" ]:
        print(host_name, host_params)
