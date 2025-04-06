class DataHandlerConfig:
    nodes_number = None
    links_number = None
    zones_number = None
    flows = None

    correspondence = list()

    def __init__(self):
        super().__init__()
        self.node_number = None
        self.init_links = None

    def setZonesNumber(self, zones_number):
        self.zones_number = zones_number

    def getZonesNumber(self):
        return self.zones_number

    def getNodesNumber(self):
        return self.node_number

    def getLinksNumber(self):
        return self.links_number

    def getLinks(self):
        return self.init_links

    def getFlows(self):
        return self.flows

    def setGraphTableData(self, links, first_thru_node):
        s_nodes = set()

        init_node = []
        term_node = []

        self.init_links = []

        for [v1, v2] in links:
            s_nodes.add(v1)
            s_nodes.add(v2)

            self.init_links.append([v1, v2])

            init_node.append(v1)
            term_node.append(v2)

        for [v1, v2] in links:

            self.init_links.append([v2, v1])

            init_node.append(v2)
            term_node.append(v1)

        self.links_number = 2 * len(links)
        self.node_number = len(s_nodes)

        graph_table = {
            "init_node": init_node,
            "term_node": term_node,
            "capacity": [10000 for _ in range(self.links_number)],
            "free_flow_time": [1 for _ in range(self.links_number)],
        }

        data_length = len(init_node)

        if (
            len(graph_table["term_node"]) != data_length
            or len(graph_table["capacity"]) != data_length
            or len(graph_table["free_flow_time"]) != data_length
        ):
            raise "Data size does not match"

        graph_table["init_node_thru"] = [
            ("s" in init_node) for init_node in graph_table["init_node"]
        ]

        graph_table["term_node_thru"] = [
            ("s" in term_node) for term_node in graph_table["term_node"]
        ]

        self.graph_table = graph_table

    def getGraphTableData(self):
        return self.graph_table

    def setCorrespondence(self, corr):
        self.correspondence = corr

    def getCorrespondence(self):
        return self.correspondence

    def setFlows(self, f):
        self.flows = f
