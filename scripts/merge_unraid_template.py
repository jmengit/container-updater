"""Merge a shipped dockerMan template while preserving installed user Config values."""
from __future__ import annotations

import argparse
import copy
import xml.etree.ElementTree as ET
from pathlib import Path


def merge(shipped: Path, installed: Path, output: Path) -> None:
    fresh_tree = ET.parse(shipped)
    fresh = fresh_tree.getroot()
    old = ET.parse(installed).getroot()
    old_configs = {
        node.get("Target", ""): node
        for node in old.findall("Config")
        if node.get("Target")
    }
    children = list(fresh)
    for index, node in enumerate(children):
        if node.tag != "Config":
            continue
        prior = old_configs.get(node.get("Target", ""))
        if prior is not None:
            fresh.remove(node)
            fresh.insert(index, copy.deepcopy(prior))
    ET.indent(fresh_tree, space="  ")
    output.parent.mkdir(parents=True, exist_ok=True)
    fresh_tree.write(output, encoding="unicode", xml_declaration=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("shipped", type=Path)
    parser.add_argument("installed", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    merge(args.shipped, args.installed, args.output)


if __name__ == "__main__":
    main()
