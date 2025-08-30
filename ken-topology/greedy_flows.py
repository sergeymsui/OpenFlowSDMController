import networkx as nx


def generate_greedy_flows(topo, targets_list):

    flows = list()
    for _, (src, dst, _) in enumerate(targets_list):
        flows.append((src, dst))

    # Функция для нахождения всех кратчайших путей
    def find_all_shortest_paths(topo, source, target):
        return list(nx.all_shortest_paths(topo, source=source, target=target))

    # Построение множества всех кратчайших путей для каждого потока
    flow_paths = []
    for idx, (s, t) in enumerate(flows):
        paths = find_all_shortest_paths(topo, s, t)
        flow_paths.append({"flow_id": idx, "source": s, "target": t, "paths": paths})

    flow_paths.sort(key=lambda x: len(x["paths"]))

    R = nx.DiGraph()

    for [u, v] in topo.edges():
        R.add_edge(u, v, edge_load=0)
        R.add_edge(v, u, edge_load=0)

    # Функция для выбора лучшего пути для потока
    def select_best_path(flow, graph):
        min_max_load = float("inf")
        best_path = None
        for path in flow["paths"]:
            # Найти максимальную загрузку на пути
            current_max = max(
                [graph[u][v]["edge_load"] for [u, v] in list(zip(path, path[1:]))]
            )
            if current_max < min_max_load:
                min_max_load = current_max
                best_path = path
        return best_path

    print("Step 4")

    # Назначение потоков
    assignment = {}
    for flow in flow_paths:
        best_path = select_best_path(flow, R)
        assignment[flow["flow_id"]] = best_path
        # Обновление загрузки каналов
        for [u, v] in list(zip(best_path, best_path[1:])):
            R[u][v]["edge_load"] += 1

    print("Step 5")

    # Определение максимальной загрузки
    max_load = max([R[u][v]["edge_load"] for [u, v] in R.edges()])

    # Вывод результатов
    print(f"Минимальное максимальное количество потоков на канале: {max_load}\n")

    all_flows = dict()

    for flow_id, path in assignment.items():
        src, dst = flows[flow_id]
        all_flows[flow_id] = path
        print(f"Поток {flow_id} назначен на путь: {' -> '.join(map(str, path))}")

    # Дополнительно: Вывод загрузки каналов
    print("\nЗагрузка каналов:")

    for [u, v] in R.edges():
        edge_load = R[u][v]["edge_load"]
        print(f"Канал {u}-{v}: {edge_load} поток(ов)")

    return all_flows
