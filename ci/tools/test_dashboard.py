#!/usr/bin/env python3
"""Validate the shipped dashboard against a captured exporter response."""

import argparse
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASHBOARD = ROOT / "dashboards/error-abuse.json"
FIXTURE = ROOT / "ci/fixtures/dashboard-exporter.prom"
METRIC = re.compile(r"\berror_abuse_[a-zA-Z0-9_:]+\b")


def validate(path):
    dashboard = json.loads(path.read_text())
    if not dashboard["schemaVersion"] >= 39:
        raise AssertionError("dashboard schema validation failed")
    if not (dashboard["title"] and dashboard["uid"]):
        raise AssertionError("dashboard schema validation failed")
    if not (
        any(
            item["name"] == "datasource" and item["pluginId"] == "prometheus"
            for item in dashboard["__inputs"]
        )
    ):
        raise AssertionError("dashboard schema validation failed")
    variables = dashboard["templating"]["list"]
    if not (len(variables) == 1 and variables[0]["name"] == "zone"):
        raise AssertionError("dashboard schema validation failed")
    if not variables[0]["datasource"]["uid"] == "${datasource}":
        raise AssertionError("dashboard schema validation failed")
    fixture = FIXTURE.read_text()
    promtool = os.environ.get("PROMTOOL", "promtool")
    subprocess.run([promtool, "check", "metrics"], input=fixture, text=True, check=True)
    kinds = dict(re.findall(r"^# TYPE (\w+) (counter|gauge)$", fixture, re.MULTILINE))
    samples = dict(
        re.findall(
            r'^([a-zA-Z_:][\w:]*)\{zone="client_errors"\} ([0-9]+)$',
            fixture,
            re.MULTILINE,
        )
    )
    if not (kinds and kinds.keys() == samples.keys()):
        raise AssertionError("invalid exporter fixture")
    used = set()
    panel_ids = set()
    expressions = []
    for panel in dashboard["panels"]:
        if not (panel["type"] == "timeseries" and panel["id"] > 0):
            raise AssertionError("dashboard schema validation failed")
        if not panel["id"] not in panel_ids:
            raise AssertionError("dashboard schema validation failed")
        panel_ids.add(panel["id"])
        if not all(key in panel["gridPos"] for key in ("x", "y", "w", "h")):
            raise AssertionError("dashboard schema validation failed")
        if not panel["datasource"]["uid"] == "${datasource}":
            raise AssertionError("dashboard schema validation failed")
        if not len(panel["targets"]) == 1:
            raise AssertionError("dashboard schema validation failed")
        expr = panel["targets"][0]["expr"]
        names = METRIC.findall(expr)
        if not len(names) == 1:
            raise AssertionError(f"expected one metric in {expr}")
        name = names[0]
        if not name in kinds:
            raise AssertionError(f"unknown metric: {name}")
        if not name not in used:
            raise AssertionError(f"duplicate metric: {name}")
        used.add(name)
        selector = f'{name}{{zone=~"${{zone}}"}}'
        expected = (
            f"rate({selector}[$__rate_interval])"
            if kinds[name] == "counter"
            else selector
        )
        if not expr == expected:
            raise AssertionError(f"unexpected query: {expr}")
        if kinds[name] == "counter" and (
            not panel["title"].endswith(" per second")
            or panel.get("fieldConfig", {}).get("defaults", {}).get("unit") != "ops"
        ):
            raise AssertionError(f"counter panel must show a per-second rate: {name}")
        expressions.append(
            (
                expr.replace("${zone}", "client_errors").replace(
                    "$__rate_interval", "2m"
                ),
                name,
            )
        )
    if not used == kinds.keys():
        raise AssertionError("dashboard must cover every exported metric")
    query = variables[0]["definition"]
    if not query == "label_values(error_abuse_requests_total, zone)":
        raise AssertionError("dashboard schema validation failed")
    with tempfile.TemporaryDirectory(prefix="ea-dashboard-") as temp:
        test = {
            "evaluation_interval": "1m",
            "tests": [
                {
                    "interval": "1m",
                    "input_series": [
                        {
                            "series": f'{name}{{zone="client_errors"}}',
                            "values": f"{value} {value} {value}",
                        }
                        for name, value in samples.items()
                    ],
                    "promql_expr_test": [
                        {
                            "expr": expr,
                            "eval_time": "2m",
                            "exp_samples": [
                                {
                                    "labels": '{zone="client_errors"}'
                                    if kinds[name] == "counter"
                                    else f'{name}{{zone="client_errors"}}',
                                    "value": 0
                                    if kinds[name] == "counter"
                                    else int(samples[name]),
                                }
                            ],
                        }
                        for expr, name in expressions
                    ],
                }
            ],
        }
        for expr, name in expressions:
            if kinds[name] == "counter":
                test["tests"].append(
                    {
                        "interval": "1m",
                        "input_series": [
                            {
                                "series": f'{name}{{zone="client_errors"}}',
                                "values": "5 10 2",
                            }
                        ],
                        "promql_expr_test": [
                            {
                                "expr": f"({expr}) > bool 0",
                                "eval_time": "2m",
                                "exp_samples": [
                                    {"labels": '{zone="client_errors"}', "value": 1}
                                ],
                            }
                        ],
                    }
                )
        test_path = Path(temp) / "queries.yml"
        test_path.write_text(json.dumps(test))
        subprocess.run(
            [promtool, "test", "rules", str(test_path)],
            check=True,
        )


class DashboardTest(unittest.TestCase):
    def test_exporter_queries(self):
        validate(DASHBOARD)

    def test_unknown_metric_rejected(self):
        data = json.loads(DASHBOARD.read_text())
        data["panels"][0]["targets"][0]["expr"] = 'error_abuse_unknown{zone=~"${zone}"}'
        with tempfile.TemporaryDirectory(prefix="ea-dashboard-mutant-") as temp:
            mutant = Path(temp) / "unknown-metric.json"
            mutant.write_text(json.dumps(data))
            with self.assertRaisesRegex(
                AssertionError, "unknown metric: error_abuse_unknown"
            ):
                validate(mutant)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--validate", type=Path)
    args = parser.parse_args()
    if args.validate:
        validate(args.validate)
    else:
        unittest.main(argv=[__file__])
