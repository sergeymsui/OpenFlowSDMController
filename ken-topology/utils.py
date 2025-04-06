import pulp
from collections import defaultdict
import networkx as nx
from sdm.data_handler_config import DataHandlerConfig


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


def generate_greedy_flows(topo, targets_list):

    flows = list()
    for _, [src, dst] in enumerate(targets_list):
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


# =======================================================================================


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

import heapq
import itertools
from collections import defaultdict

def networkx_flow_decomposition_fwa(result, correspondence, k_paths=10):
    links = result["links"]
    flows = result["flows"]

    # Построим граф с весами из flows
    G = nx.DiGraph()
    for (u, v), flow in zip(links, flows):
        if flow > 1e-6:
            G.add_edge(u, v, weight=1.0 / (flow + 1e-6), flow=flow)  # "желаемое направление"

    # Добавим обратные потоки
    full_corr = []
    for [src_dst, demand] in correspondence:
        src, dst = src_dst
        full_corr.append([[src, dst], demand])
        full_corr.append([[dst, src], demand])  # ответ сервера

    edge_load = defaultdict(int)  # сколько потоков по рёбрам
    inner_flows = defaultdict(int)

    for [src_dst, demand] in full_corr:
        src, dst = src_dst

        # Найдём k кратчайших путей по "желаемой" метрике (инверсии потока)
        try:
            paths = list(itertools.islice(nx.shortest_simple_paths(G, src, dst, weight='weight'), k_paths))
        except nx.NetworkXNoPath:
            print(f"❌ No path between {src} and {dst}")
            continue

        # Оценим каждый путь: насколько хорошо он соответствует расчетному распределению потоков
        def path_score(path):
            return sum(1.0 / (G[u][v]['flow'] + 1e-6) for u, v in zip(path[:-1], path[1:]))

        scored_paths = [(path_score(p), p) for p in paths]
        heapq.heapify(scored_paths)

        # Распределим потоки по путям пропорционально весу (жадно, дискретно)
        for _ in range(demand):
            _, best_path = heapq.heappop(scored_paths)

            # Увеличим нагрузку по рёбрам
            for u, v in zip(best_path[:-1], best_path[1:]):
                edge_load[(u, v)] += 1

            # Зарегистрируем поток
            inner_flows[(src, dst, tuple(best_path))] += 1

            # Обновим оценку этого пути и вернём в очередь
            new_score = sum(
                (edge_load[(u, v)] + 1) / (G[u][v]['flow'] + 1e-6)
                for u, v in zip(best_path[:-1], best_path[1:])
            )
            heapq.heappush(scored_paths, (new_score, best_path))

    return inner_flows

def networkx_flow_decomposition(result, correspondence):

    links = result["links"]
    flows = result["flows"]

    auxiliary = nx.DiGraph()
    for [u, v] in links:
        auxiliary.add_edge(u, v, flow=0)

    residual = nx.DiGraph()
    for [u, v] in links:
        residual.add_edge(u, v, flow=0)

    for i, [u, v] in enumerate(links):
        residual[u][v]["flow"] += flows[i]

    inner_flows = defaultdict(int)

    total_correspondence = 0
    for [_, w] in correspondence:
        total_correspondence += w

    def full_flow_weight(common_correspondence):
        return sum(common_correspondence)

    eps = 0
    step = 1
    common_correspondence = [0 for _ in correspondence]

    while (total_correspondence - full_flow_weight(common_correspondence)) > eps:

        for i, [[src, dst], _] in enumerate(correspondence):

            # TODO: сделать список уже заполненных потоков (для повышения точности)
            simple_paths = [path for path in nx.all_shortest_paths(auxiliary, src, dst)]

            diff_max_weight, diff_max_path = 0, []
            for path in simple_paths:
                min_residual_weight = min(
                    [residual[u][v]["flow"] for u, v in list(zip(path[:-1], path[1:]))]
                )
                min_auxiliary_weight = min(
                    [auxiliary[u][v]["flow"] for u, v in list(zip(path[:-1], path[1:]))]
                )

                diff = min_residual_weight - min_auxiliary_weight

                if diff > diff_max_weight:
                    diff_max_path = path

            if not len(diff_max_path):
                continue

            orig_path = diff_max_path

            print(
                "Abs = ",
                (total_correspondence - full_flow_weight(common_correspondence)),
            )
            print(" common_correspondence = ", common_correspondence)
            print("target_correspondence = ", [w for [_, w] in correspondence])

            if len(orig_path):

                additional = step

                for u, v in list(zip(orig_path[:-1], orig_path[1:])):
                    auxiliary[u][v]["flow"] += additional

                common_correspondence[i] += additional
                inner_flows[(src, dst, tuple(orig_path))] += additional

            if (total_correspondence - full_flow_weight(common_correspondence)) <= eps:
                break

    return inner_flows


def generate_msa_flows(
    topo,
    targets_list,
):
    print("Generate flows")
    all_flows = dict()

    config = DataHandlerConfig()
    config.setGraphTableData(
        links=topo.edges(),
        first_thru_node=1,
    )

    correspondence = list()
    for _, [src, dst] in enumerate(targets_list):
        correspondence.append([[src, dst], 1])

    config.setZonesNumber(len(correspondence))
    config.setCorrespondence(correspondence)
    config.setFlows([d for d, _ in correspondence])

    result = msa(config)
    dflows = networkx_flow_decomposition(result, correspondence)

    for idx, [[src, dst], _] in enumerate(correspondence):

        for key in dflows.keys():
            (s, d, path) = key

            if src == s and dst == d:
                all_flows[idx] = path

    return all_flows

import time
import numpy as np
from sdm.data_handler import DataHandler
from sdm.model import Model

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

def generate_fwa_flows(
    topo,
    targets_list,
):
    all_flows = dict()

    config = DataHandlerConfig()
    config.setGraphTableData(
        links=topo.edges(),
        first_thru_node=1,
    )

    correspondence = list()

    # for _, [src, dst] in enumerate(targets_list):
    #     correspondence.append([[src, dst], 1])

    correspondence.append([["h1", "h3"], 10])
    correspondence.append([["h2", "h4"], 10])

    config.setZonesNumber(len(correspondence))
    config.setCorrespondence(correspondence)
    config.setFlows([d for d, _ in correspondence])

    result = fwa(config)
    dflows = networkx_flow_decomposition_fwa(result, correspondence)

    for trace, flow in dflows.items():
        print(f"trace: {trace}, flow: {flow}")

    idx, path_list = 0, list()

    for (src, dst, (path)), flow in dflows.items():
        mpath = list(path)
        for _ in range(flow):
            all_flows[idx] = mpath
            idx += 1

        if mpath not in path_list:
            path_list.append(mpath)
    
    for mpath in path_list:
        all_flows[idx] = mpath[::-1]
        idx += 1

    return all_flows

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



def generate_ustm_flows(
    G: nx.Graph,
    hosts,
    nflows,
    corr_weight,
    size=None,
    start_time=None,
    finish_time=None,
    arrival_dist=None,
    size_dist=None,
):
    """ """

    all_flows = dict()

    config = DataHandlerConfig()
    config.setGraphTableData(
        links=G.edges(),
        first_thru_node=1,
    )

    correspondence = list()

    targets_list = long_path_targets(G, hosts, nflows)
    for _, [src, dst] in enumerate(targets_list):
        correspondence.append([[src, dst], nflows * corr_weight])

    config.setZonesNumber(len(correspondence))
    config.setCorrespondence(correspondence)
    config.setFlows([d for d, _ in correspondence])

    result = ustm(config)
    dflows = networkx_flow_decomposition_fwa(result, correspondence)

    for idx, [[src, dst], _] in enumerate(correspondence):

        paths = list()
        flows = list()

        for key in dflows.keys():
            (s, d, path) = key

            if src == s and dst == d:
                paths.append(list(path))
                flows.append(dflows[key])

        all_flows[idx] = DiffFlow(
            idx,
            src,
            dst,
            size=size,
            flows=flows,
            paths=paths,
            start_time=start_time,
            finish_time=finish_time,
            arrival_dist=arrival_dist,
            size_dist=size_dist,
        )

    return all_flows
