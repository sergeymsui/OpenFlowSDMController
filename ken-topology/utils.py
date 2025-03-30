import pulp
from collections import defaultdict
import networkx as nx


def generate_ilp_flows(topo, targets_list):
    """
    Генерирует потоки трафика с использованием ILP для назначения маршрутов
    """

    flows = list()
    for _, [src, dst] in enumerate(targets_list):
        flows.append((src, dst))

    all_flows = dict()

    # Шаг 1: Поиск всех кратчайших маршрутов для каждого потока
    flow_paths = {}
    for idx, (s, t) in enumerate(flows):
        try:
            paths = list(
                nx.all_shortest_paths(topo, source=s, target=t, weight="weight")
            )
            flow_paths[idx] = paths
        except nx.NetworkXNoPath:
            print(f"Нет маршрута между {s} и {t}. Поток {idx} будет пропущен.")
            continue

    # Шаг 2: Создание ILP модели
    model = pulp.LpProblem("Flow_Distribution_ILP", pulp.LpMinimize)

    # Шаг 3: Создание переменных
    x = {}
    for i in flow_paths:
        for j, path in enumerate(flow_paths[i]):
            var_name = f"x_{i}_{j}"
            x[(i, j)] = pulp.LpVariable(var_name, cat="Binary")

    # Переменная для максимальной загрузки
    L = pulp.LpVariable("L", lowBound=0, cat="Integer")

    # Целевая функция: минимизировать L
    model += L, "Minimize_max_load"

    # Ограничение: Каждый поток назначен на ровно один путь
    for i in flow_paths:
        model += (
            pulp.lpSum([x[(i, j)] for j in range(len(flow_paths[i]))]) == 1,
            f"Flow_{i}_assignment",
        )

    # Ограничение: Загрузка каждого канала не превышает L
    edge_loads = defaultdict(list)
    for i in flow_paths:
        for j, path in enumerate(flow_paths[i]):
            for k in range(len(path) - 1):
                e = tuple(sorted([path[k], path[k + 1]]))
                edge_loads[e].append(x[(i, j)])

    for e in edge_loads:
        model += pulp.lpSum(edge_loads[e]) <= L, f"Edge_{e}_load"

    # Шаг 4: Решение модели
    solver = pulp.PULP_CBC_CMD(msg=True)
    model.solve(solver)

    # Проверка статуса решения
    if pulp.LpStatus[model.status] != "Optimal":
        raise ValueError("ILP модель не нашла оптимального решения.")

    edge_load = defaultdict(int)
    path_set = set()

    # Шаг 5: Назначение маршрутов потокам
    for i in flow_paths:
        for j, path in enumerate(flow_paths[i]):
            if pulp.value(x[(i, j)]) == 1:
                # Создание объекта потока с назначенным маршрутом
                all_flows[i] = path

                path_set.add(tuple(path))

                for edge in list(zip(path, path[1:])):
                    edge_load[tuple(edge)] += 1

                break  # Переходим к следующему потоку

    for path in path_set:
        max_load = max([edge_load[edge] for edge in list(zip(path, path[1:]))])
        print(f"Max load: {max_load} for path {path}")

    return all_flows
