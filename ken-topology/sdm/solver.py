import time
import numpy as np

from .model import Model
from .data_handler import DataHandler
import networkx as nx

def fwa(config):
    max_iter = 1000

    handler = DataHandler()
    graph_data = handler.GetGraphData(config)

    graph_correspondences, total_od_flow = handler.GetGraphCorrespondences(config)

    print("graph_correspondences = ", graph_correspondences)
    print("total_od_flow = ", total_od_flow)

    model = Model(graph_data, graph_correspondences, total_od_flow, mu=0.25, rho=0.15)

    print("Frank-Wolfe without stopping criteria")
    solver_kwargs = {
        "max_iter": max_iter,
        "stop_crit": "max_iter",
        "verbose": True,
        "verbose_step": 200,
        "save_history": True,
    }
    tic = time.time()
    result = model.find_equilibrium(solver_name="fwm", solver_kwargs=solver_kwargs)
    toc = time.time()
    print("Elapsed time: {:.0f} sec".format(toc - tic))
    print(
        "Time ratio =",
        np.max(result["times"] / graph_data["graph_table"]["free_flow_time"]),
    )
    print(
        "Flow excess =",
        np.max(result["flows"] / graph_data["graph_table"]["capacity"]) - 1,
        end="\n\n",
    )

    result["links"] = config.getLinks()

    print("times:", result["times"])
    print("flows:", result["flows"])
    print("links:", result["links"])

    return result


def msa_lambda(i):
    return 1 / (i + 1)


def msa_t(x):
    return 10 + x / 100


def msa(config):
    x = nx.Graph()
    x_s = nx.Graph()

    OLD_AEC = None

    edges = []

    for [u, v] in config.getLinks():
        edges.append((u, v))

    for u, v in edges:
        x.add_edge(u, v, weight=0, time=msa_t(0))

    for u, v in edges:
        x_s.add_edge(u, v, weight=0)

    for [[o, d], w] in config.getCorrespondence():
        dijkstra_path = nx.dijkstra_path(x, o, d, weight="time")

        j = 1
        while j < len(dijkstra_path):
            u = dijkstra_path[j - 1]
            v = dijkstra_path[j]

            x[u][v]["weight"] += w
            x_s[u][v]["weight"] += w

            x[u][v]["time"] = msa_t(x[u][v]["weight"])

            j += 1

    i = 1
    while i < 1000:

        tx = 0
        for u, v in edges:
            tx += x[u][v]["weight"] * x[u][v]["time"]

        kq = 0
        for [[o, d], w] in config.getCorrespondence():
            dijkstra_path = nx.dijkstra_path(x, o, d, weight="time")

            t = 0
            j = 1
            while j < len(dijkstra_path):
                u = dijkstra_path[j - 1]
                v = dijkstra_path[j]

                t += x[u][v]["time"]

                j += 1

            kq += t * w

        wc = 0
        for [[o, d], w] in config.getCorrespondence():
            wc += w

        AEC = (tx - kq) / wc

        if OLD_AEC:
            if abs(OLD_AEC - AEC) < 0.1:
                break

        OLD_AEC = AEC

        for u, v in edges:
            x_s[u][v]["weight"] = 0

        for [[o, d], w] in config.getCorrespondence():
            dijkstra_path = nx.dijkstra_path(x, o, d, weight="time")

            j = 1
            while j < len(dijkstra_path):
                u = dijkstra_path[j - 1]
                v = dijkstra_path[j]

                x_s[u][v]["weight"] += w

                j += 1

        l = msa_lambda(i)
        for u, v in edges:
            x[u][v]["weight"] = l * x_s[u][v]["weight"] + (1 - l) * x[u][v]["weight"]
            x[u][v]["time"] = msa_t(x[u][v]["weight"])

        i += 1

    result = dict()
    result["flows"] = [x[u][v]["weight"] for u, v in edges]
    result["links"] = [[u, v] for [u, v] in config.getLinks()]

    return result


def ustm(config):

    handler = DataHandler()
    graph_data = handler.GetGraphData(config)

    graph_correspondences, total_od_flow = handler.GetGraphCorrespondences(config)

    init_capacities = np.copy(graph_data["graph_table"]["capacity"])
    print(graph_data["graph_table"].head())
    # start from 0.5,  0.75, 0.875 (according to our flows reconstruction method)
    alpha = 0.75
    graph_data["graph_table"]["capacity"] = init_capacities * alpha
    model = Model(graph_data, graph_correspondences, total_od_flow, mu=0)
    graph_data["graph_table"].head()
    print("model.mu == 0: ", (model.mu == 0))
    max_iter = 1000
    solver_kwargs = {
        "eps_abs": 100,
        "max_iter": max_iter,
        "stop_crit": "max_iter",
        "verbose": True,
        "verbose_step": 500,
        "save_history": True,
    }
    tic = time.time()
    result = model.find_equilibrium(
        solver_name="ustm",
        composite=True,
        solver_kwargs=solver_kwargs,
        base_flows=alpha * graph_data["graph_table"]["capacity"],
    )
    # base_flows here doesn't define anything now
    toc = time.time()
    print("Elapsed time: {:.0f} sec".format(toc - tic))
    print(
        "Time ratio =",
        np.max(result["times"] / graph_data["graph_table"]["free_flow_time"]),
    )
    print(
        "Flow excess =",
        np.max(result["flows"] / graph_data["graph_table"]["capacity"]) - 1,
        end="\n\n",
    )
    result["elapsed_time"] = toc - tic
    base_flows = result["flows"]
    ## Step 2: SD Model solution
    graph_data["graph_table"]["capacity"] = init_capacities
    model = Model(graph_data, graph_correspondences, total_od_flow, mu=0)
    graph_data["graph_table"].head()
    # USTM method
    max_iter = 1000
    solver_kwargs = {
        "eps_abs": 100,
        "max_iter": max_iter,
        "stop_crit": "max_iter",
        "verbose": True,
        "verbose_step": 400,
        "save_history": True,
    }
    tic = time.time()
    result = model.find_equilibrium(
        solver_name="ustm",
        composite=True,
        solver_kwargs=solver_kwargs,
        base_flows=base_flows,
    )
    toc = time.time()
    print("Elapsed time: {:.0f} sec".format(toc - tic))
    print(
        "Time ratio =",
        np.max(result["times"] / graph_data["graph_table"]["free_flow_time"]),
    )
    print(
        "Flow excess =",
        np.max(result["flows"] / graph_data["graph_table"]["capacity"]) - 1,
        end="\n\n",
    )
    # NOTE: duality gap should be nonnegative here!

    result["links"] = [[u, v] for [u, v] in config.getLinks()]

    return result
