# This file is part of the mkcheck project.
# Licensing information can be found in the LICENSE file.
# (C) 2018 Nandor Licker. ALl rights reserved.

import os
import json
from collections import defaultdict



class DependencyGraph(object):
    """Graph describing dependencies between file paths."""

    class Node(object):
        def __init__(self, path):
            self.path = path
            self.edges = set()

    def __init__(self):
        self.nodes = {}
        self.rev_nodes = {}

    def add_dependency(self, src, dst):
        if src not in self.nodes:
            self.nodes[src] = self.Node(src)
            self.rev_nodes[src] = self.Node(src)
        if dst not in self.nodes:
            self.nodes[dst] = self.Node(dst)
            self.rev_nodes[dst] = self.Node(dst)
        self.nodes[src].edges.add(dst)
        self.rev_nodes[dst].edges.add(src)

    def find_deps(self, src):
        deps = set()
        def traverse(name):
            if name in deps:
                return
            deps.add(name)
            if name in self.nodes:
                for edge in self.nodes[name].edges:
                    traverse(edge)
        traverse(src)
        return deps

    def find_rev_deps(self, src):
        deps = dict()
        def traverse(name, parent, depth):
            if name in parent or depth > 3:
                return
            parent[name] = dict()
            if name in self.rev_nodes:
                for edge in self.rev_nodes[name].edges:
                    traverse(edge, parent[name], depth + 1)
        traverse(src, deps, 0)
        return deps

    def is_direct(self, src, dst):
        return dst in self.nodes[src].edges

    def prune_transitive(self, nodes):
        non_transitive = nodes
        for node in nodes:
            if node not in non_transitive:
                continue
            non_transitive = non_transitive - (self.find_deps(node) - {node})
        return non_transitive

    def topo_order(self):
        """Finds the first and last position a node can be scheduled to."""

        topo = []
        visited = set()
        def topo_dfs(node):
            if node in visited:
                return
            visited.add(node)

            for next in self.nodes[node].edges:
                topo_dfs(next)
            topo.append(node)

        for node in self.nodes.keys():
            topo_dfs(node)
    
        return reversed(topo)


def parse_graph(path):
    """Finds files written and read during a clean build."""

    # Find all files and processes.
    files = {}
    inputs = set()
    outputs = set()
    built_by = {}
    with open(path, 'r') as f:
        data = json.loads(f.read())
        for file in data["files"]:
            files[file['id']] = file
        for proc in data["procs"]:
            proc_in = set(proc.get('input', []))
            proc_out = set(proc.get('output', []))
            
            inputs = inputs | proc_in
            outputs = outputs | proc_out
            image = os.path.basename(files[proc['image']]['name'])
            for output in proc_out:
                output_name = files[output]['name']
                builders = built_by.get(output_name, set())
                builders.add((image, proc['uid']))
                built_by[output_name] = builders
    
    def persisted(uid):
        if files[uid].get('deleted', False):
            return False
        if not files[uid].get('exists', False):
            return False
        name = files[uid]['name']
        if name.startswith('/dev') or name.startswith('/proc'):
            return False
        return os.path.exists(name) and not os.path.isdir(name)

    inputs = {files[uid]['name'] for uid in inputs if persisted(uid)}
    outputs = {files[uid]['name'] for uid in outputs if persisted(uid)}

    gid = {}
    for proc in sorted(data["procs"], key=lambda p: p["uid"]):
      uid = proc["uid"]
      if proc.get('cow', False) and proc["parent"] in gid:
        gid[uid] = gid[proc["parent"]]
      else:
        gid[uid] = uid

    groups = defaultdict(lambda: (set(), set()))
    for proc in data["procs"]:
      group_id = gid[proc["uid"]]

      ins, outs = groups[group_id]
      ins.update(proc.get('input', []))
      outs.update(proc.get('output', []))
   
    # edges[k] depends on k
    edges = defaultdict(list)
    for uid, file in files.items():
        for dep in file.get('deps', []):
            edges[files[dep]['name']].append(files[uid]['name'])
   
    for _, (ins, outs) in groups.items():
        for input in ins - outs:
            if files[input]['name'] in ['/dev/stderr', '/dev/stdout']:
                continue
            if os.path.isdir(files[input]['name']):
                continue
            for output in outs:
                if files[output]['name'] in ['/dev/stderr', '/dev/stdout']:
                    continue
                if os.path.isdir(files[output]['name']):
                    continue
                edges[files[input]['name']].append(files[output]['name'])

    nodes = inputs | outputs

    back_edges = defaultdict(list)
    for src, dsts in edges.items():
        for dst in dsts:
            back_edges[dst].append(src)

    graph = DependencyGraph()
    for src in nodes:
        visited = set()
        def add_edges(to):
            _ = back_edges
            if to in visited:
                return
            visited.add(to)
            for node in edges.get(to, []):
                if node in nodes:
                    if src != node:
                        if node == "/home/katei/ghq/github.com/ruby/build/x86_64-linux/yjit/target/release/libyjit.a" and \
                            src.endswith(".o"):
                            breakpoint()

                        graph.add_dependency(src, node)
                else:
                    add_edges(node)
        add_edges(src)

    return inputs, outputs, built_by, graph
