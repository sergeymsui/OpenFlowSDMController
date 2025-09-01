
import networkx as nx

def generate_load_aware_paths(G: nx.DiGraph, demands: list):
    """
    Load-aware маршрутизация.
    После каждого выбранного маршрута увеличивает вес рёбер с учётом объёма трафика.
    """
    import copy

    # Создаем копию графа чтобы не портить оригинал
    G_working = copy.deepcopy(G)

    # Инициализируем веса если их нет
    for u, v in G_working.edges():
        if "weight" not in G_working[u][v]:
            G_working[u][v]["weight"] = 1.0
        if "load" not in G_working[u][v]:
            G_working[u][v]["load"] = 0.0

    routes = {}

    for k, (src, dst, volume) in enumerate(demands):
        try:
            # Выбор пути с учётом текущих весов
            path = nx.shortest_path(G_working, source=src, target=dst, weight="weight")
            routes[k] = path

            # После выбора пути обновляем загрузку рёбер
            for u, v in zip(path[:-1], path[1:]):
                G_working[u][v]["load"] += volume
                # Вес зависит от загрузки — например, линейная зависимость
                G_working[u][v]["weight"] = 1.0 + G_working[u][v]["load"]

        except nx.NetworkXNoPath:
            routes[k] = []
            print(f"[WARN] Нет пути между {src} и {dst}")

    return routes


def generate_ospf_like_paths(G: nx.DiGraph, demands: list):
    """
    Расчёт маршрутов аналогично работе OSPF.

    Для каждого demand (src, dst, volume) считаем кратчайший путь
    по стоимости веса на рёбрах, который имитирует OSPF cost.

    Если веса не заданы — считаем cost=1, что эквивалентно обычному OSPF в простейшей сети.

    :param G: Сетевая топология (Graph)
    :param demands: Список demand (src, dst, volume)
    :return: Словарь маршрутов {индекс: путь}
    """
    routes = {}

    for k, (src, dst, volume) in enumerate(demands):
        try:
            # OSPF строит маршруты по сумме cost (если веса не заданы — просто hop count)
            path = nx.shortest_path(G, source=src, target=dst, weight="cost")
            routes[k] = path
        except nx.NetworkXNoPath:
            routes[k] = []
            print(f"[OSPF_WARN] Нет пути между {src} и {dst}")

    return routes


def generate_adaptive_shortest_paths(
    G: nx.DiGraph, demands: list, weight_attr="weight", increment=1
):
    """
    Расчёт маршрутов через кратчайшие пути (Дейкстра) с динамическим увеличением веса рёбер.
    После выбора каждого маршрута веса рёбер на его пути увеличиваются.
    """
    # Если в графе ещё нет весов — инициализируем все веса равными 1
    for u, v in G.edges():
        if weight_attr not in G[u][v]:
            G[u][v][weight_attr] = 1

    routes = {}

    for k, (src, dst, volume) in enumerate(demands):
        try:
            path = nx.shortest_path(G, source=src, target=dst, weight=weight_attr)
            routes[k] = path

            # Увеличиваем веса на рёбрах пути
            for i in range(len(path) - 1):
                u, v = path[i], path[i + 1]
                G[u][v][weight_attr] += increment

        except nx.NetworkXNoPath:
            routes[k] = []
            print(f"[WARN] Нет пути между {src} и {dst}")

    return routes