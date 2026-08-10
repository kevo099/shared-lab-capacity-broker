"""Command-line entry point for offline planning and read-only serving/export."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .domain.planner import build_overview, plan_start
from .domain.types import InputError, PlanRequest
from .evidence_probe import export_probe_evidence
from .fixtures import load_demo
from .live_export import ProxmoxHTTPSReader, export_live_snapshot
from .web import SnapshotFileApplication, WebSettings, add_serve_arguments, serve


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Shared Lab Capacity Broker (read-only)")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("overview", help="print the complete synthetic environment matrix")
    plan = subparsers.add_parser("plan", help="compute one deterministic read-only plan")
    plan.add_argument("environment_id")
    plan.add_argument("--duration-seconds", type=int)
    web = subparsers.add_parser(
        "serve",
        help="serve the synthetic demo or a sanitized live snapshot on loopback",
    )
    add_serve_arguments(web)
    export = subparsers.add_parser(
        "export-live",
        help="collect Proxmox GET evidence and atomically export a sanitized snapshot",
    )
    export.add_argument("--catalog-file", type=Path, required=True)
    export.add_argument("--bindings-file", type=Path, required=True)
    export.add_argument("--evidence-file", type=Path, required=True)
    export.add_argument("--output", type=Path, required=True)
    export.add_argument("--pve-port", type=int, default=8006)
    tls = export.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", type=Path)
    tls.add_argument(
        "--insecure-tls",
        action="store_true",
        help="explicit trusted-LAN escape hatch; prefer a reviewed CA file",
    )
    probe = subparsers.add_parser(
        "probe-evidence",
        help="collect strict read-only safety evidence and atomically export it",
    )
    probe.add_argument("--catalog-file", type=Path, required=True)
    probe.add_argument("--bindings-file", type=Path, required=True)
    probe.add_argument("--probe-config-file", type=Path, required=True)
    probe.add_argument("--output", type=Path, required=True)
    probe.add_argument("--pve-port", type=int, default=8006)
    probe_tls = probe.add_mutually_exclusive_group()
    probe_tls.add_argument("--ca-file", type=Path)
    probe_tls.add_argument(
        "--insecure-tls",
        action="store_true",
        help="explicit trusted-LAN escape hatch; prefer a reviewed CA file",
    )
    return parser


def _print(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, indent=2))


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "serve":
            if (args.catalog_file is None) != (args.snapshot_file is None):
                raise InputError("--catalog-file and --snapshot-file must be supplied together")
            application = (
                SnapshotFileApplication(args.catalog_file, args.snapshot_file)
                if args.catalog_file is not None
                else None
            )
            serve(WebSettings(args.bind, args.port, args.allow_nonloopback), application)
            return 0
        if args.command == "export-live":
            reader = ProxmoxHTTPSReader.from_environment(
                port=args.pve_port,
                ca_file=args.ca_file,
                insecure_tls=args.insecure_tls,
            )
            result = export_live_snapshot(
                catalog_path=args.catalog_file,
                bindings_path=args.bindings_file,
                evidence_path=args.evidence_file,
                output_path=args.output,
                reader=reader,
            )
            _print(
                {
                    "ok": True,
                    "revision": result["revision"],
                    "generated_at": result["generated_at"],
                    "output": str(args.output),
                }
            )
            return 0
        if args.command == "probe-evidence":
            reader = ProxmoxHTTPSReader.from_environment(
                port=args.pve_port,
                ca_file=args.ca_file,
                insecure_tls=args.insecure_tls,
            )
            result = export_probe_evidence(
                catalog_path=args.catalog_file,
                bindings_path=args.bindings_file,
                probe_config_path=args.probe_config_file,
                output_path=args.output,
                reader=reader,
            )
            _print(
                {
                    "ok": True,
                    "observed_at": max(result["source_observed_at"].values()),
                    "output": str(args.output),
                }
            )
            return 0
        catalog, snapshot = load_demo()
        if args.command == "overview":
            _print(build_overview(snapshot, catalog, evaluated_at=snapshot.demo_evaluation_time))
            return 0
        request = PlanRequest.create(
            args.environment_id,
            snapshot.demo_evaluation_time,
            args.duration_seconds,
        )
        _print(plan_start(request, snapshot, catalog))
        return 0
    except (InputError, ValueError) as exc:
        print(f"lab-broker refused input: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
