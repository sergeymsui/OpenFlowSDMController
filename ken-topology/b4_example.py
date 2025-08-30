import networkx as nx
from pulp import LpProblem, LpMinimize, LpVariable, lpSum, LpStatus
from collections import defaultdict

def generate_b4_flows_paths_pulp(G: nx.DiGraph, demands: list):
    """
    Расчёт маршрутов B4 TE через LP с использованием PuLP.
    Возвращает для каждой пары (индекс в demands) один маршрут (сплавленные рёбра с положительным потоком).
    """
    edges = list(G.edges())
    edge_caps = {(u, v): G[u][v].get('capacity', 1e9) for u, v in edges}

    K = list(range(len(demands)))
    sources = [d[0] for d in demands]
    sinks = [d[1] for d in demands]
    volumes = [d[2] for d in demands]

    # Переменные: потоки по рёбрам
    flow = {
        (k, u, v): LpVariable(f"f_{k}_{u}_{v}", lowBound=0)
        for k in K for u, v in edges
    }

    alpha = LpVariable("alpha", lowBound=0)

    prob = LpProblem("B4_Traffic_Engineering", LpMinimize)
    prob += alpha  # минимизируем максимальную загрузку

    # Ограничения пропускной способности
    for u, v in edges:
        prob += lpSum(flow[k, u, v] for k in K) <= alpha * edge_caps[u, v]

    # Сохранение потока
    for k in K:
        for node in G.nodes:
            inflow = lpSum(flow[k, u, node] for u in G.predecessors(node))
            outflow = lpSum(flow[k, node, v] for v in G.successors(node))
            if node == sources[k]:
                prob += (outflow - inflow == volumes[k])
            elif node == sinks[k]:
                prob += (inflow - outflow == volumes[k])
            else:
                prob += (inflow == outflow)

    prob.solve()

    if LpStatus[prob.status] != 'Optimal':
        raise RuntimeError("Оптимальное решение не найдено.")

    # Восстановление маршрутов: для каждого потока пройти по активным рёбрам
    routes = {}
    for k in K:
        used_edges = [(u, v) for u, v in edges if flow[k, u, v].varValue and flow[k, u, v].varValue > 1e-6]
        # Построим подграф потока и найдём путь из источника в приёмник
        flow_graph = nx.DiGraph()
        flow_graph.add_edges_from(used_edges)
        try:
            routes[k] = [its for its in nx.shortest_path(flow_graph, source=sources[k], target=sinks[k])]
        except nx.NetworkXNoPath:
            routes[k] = []
    return routes



if __name__ == "__main__":
    # Пример: граф и demands
    G = nx.DiGraph()
    G.add_edge("A", "B", capacity=100)
    G.add_edge("B", "C", capacity=100)
    G.add_edge("A", "C", capacity=50)

    demands = [("A", "C", 80)]

    flow_paths = generate_b4_flows_paths_pulp(G, demands)

    for idx, path in flow_paths.items():
        print(f"Flow idx: {idx} path: {path}")
