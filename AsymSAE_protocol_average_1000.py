#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Run AsymSAE_protocol_updated.py repeatedly and print average timings.

Default behavior:
  - Run the protocol 1000 successful times per curve.
  - Output the average time of every timed operation.
  - Test these four curves:
      prime192v1, prime256v1, secp192k1, secp256k1

Usage:
  Put this file in the same directory as AsymSAE_protocol_updated.py, then run:

      python3 AsymSAE_protocol_average_1000.py

Optional:
      python3 AsymSAE_protocol_average_1000.py --runs 1000
      python3 AsymSAE_protocol_average_1000.py --curves prime192v1 secp256k1
"""

import argparse
import os
import sys
import time
from collections import OrderedDict

from charm.toolbox.ecgroup import ECGroup
from charm.toolbox.eccurve import prime192v1, prime256v1, secp192k1, secp256k1

# Ensure the original protocol file can be imported when both files are in
# the same directory.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

import AsymSAE_protocol_updated as proto


CURVES = OrderedDict([
    ("prime192v1", prime192v1),
    ("prime256v1", prime256v1),
    ("secp192k1", secp192k1),
    ("secp256k1", secp256k1),
])


def configure_curve(curve_name, curve_obj):
    """
    Reconfigure the imported AsymSAE_protocol_updated module to use a new curve.

    The original protocol code stores group/order/key-size values as globals.
    Python functions resolve these globals at call time, so updating them here
    lets the same protocol implementation run on different curves.
    """
    proto.group = ECGroup(curve_obj)
    proto.p = proto.group.order()

    # Keep the same L setting as AsymSAE_protocol_updated.py.
    # This preserves the original output/logic style while only changing curves.
    proto.L_BITS = 256
    proto.L_BYTES = proto.L_BITS // 8
    proto.ZERO_KEY = b"\x00" * proto.L_BYTES

    return proto.group, proto.p


def new_timing_accumulator():
    """Create an ordered timing accumulator."""
    return OrderedDict()


def add_timings(acc, timings):
    """Add one round's timing dictionary into an ordered accumulator."""
    for label, elapsed in timings.items():
        if label not in acc:
            acc[label] = 0.0
        acc[label] += elapsed


def average_timings(acc, successful_runs):
    """Convert accumulated timings to average timings."""
    return OrderedDict(
        (label, total_elapsed / successful_runs)
        for label, total_elapsed in acc.items()
    )


def run_one_protocol():
    """
    Run the complete protocol once.

    Returns:
      t_init, c1_t, s1_t, c2_t, s2_t, c3_t

    Raises:
      Exception if the protocol aborts or if the two PMKs do not match.
    """
    MAC_C = "00:11:22:33:44:55"
    MAC_S = "AA:BB:CC:DD:EE:FF"
    SSID = "ESAE_Network"
    salt = os.urandom(16).hex()
    pw = "my_secret_password"

    t0 = time.perf_counter()
    pi0_stored, V_stored = proto.initialization(pw, SSID, salt)
    t_init = time.perf_counter() - t0

    client_state, client_msg, c1_t = proto.client_round1(
        pw, SSID, salt, MAC_C, MAC_S
    )

    server_state, server_msg, s1_t = proto.server_round1(
        pi0_stored, V_stored, SSID, salt, MAC_C, MAC_S, client_msg
    )

    client_state, client_msg2, c2_t = proto.client_round2(
        client_state, server_msg
    )

    pmk_s, server_msg2, s2_t = proto.server_round2(
        server_state, client_msg2
    )

    pmk_c, c3_t = proto.client_round3(
        client_state, server_msg2
    )

    if pmk_c != pmk_s:
        raise Exception("Session keys DO NOT match — protocol FAILED!")

    return t_init, c1_t, s1_t, c2_t, s2_t, c3_t


def print_average_header(curve_name, runs):
    print("=" * 72)
    print("  AsymSAE Protocol Simulation Average Timings")
    print(f"  Curve: {curve_name}")
    print(f"  Successful runs: {runs}")
    print("=" * 72)


def print_initialization_average(t_init_avg):
    print("\n>>> Initialization Phase (offline, one-time)")
    print(f"      Average initialization time over runs: {t_init_avg * 1000:.6f} ms")
    print("      AP stores (π0, V = π1·H2C(π0|SSID), SSID, s)")


def benchmark_curve(curve_name, curve_obj, runs):
    """
    Benchmark one curve for the requested number of successful protocol runs.
    """
    configure_curve(curve_name, curve_obj)

    init_total = 0.0
    c1_acc = new_timing_accumulator()
    s1_acc = new_timing_accumulator()
    c2_acc = new_timing_accumulator()
    s2_acc = new_timing_accumulator()
    c3_acc = new_timing_accumulator()

    successful = 0
    failed_or_skipped = 0

    # Random protocol values can very rarely trigger an abort condition
    # such as s in {0,1}. Those runs are skipped so that the averages are
    # computed over exactly `runs` successful executions.
    max_attempts = max(runs * 2, runs + 100)

    while successful < runs:
        if successful + failed_or_skipped >= max_attempts:
            raise RuntimeError(
                f"Too many failed/skipped attempts on curve {curve_name}: "
                f"{failed_or_skipped} skipped before reaching {runs} successful runs."
            )

        try:
            t_init, c1_t, s1_t, c2_t, s2_t, c3_t = run_one_protocol()
        except Exception as exc:
            failed_or_skipped += 1
            continue

        init_total += t_init
        add_timings(c1_acc, c1_t)
        add_timings(s1_acc, s1_t)
        add_timings(c2_acc, c2_t)
        add_timings(s2_acc, s2_t)
        add_timings(c3_acc, c3_t)
        successful += 1

    t_init_avg = init_total / successful

    print_average_header(curve_name, successful)
    print_initialization_average(t_init_avg)

    print("\n>>> Active Scanning")
    print("      STA → AP : MAC_C = 00:11:22:33:44:55")
    print("      AP  → STA: MAC_S = AA:BB:CC:DD:EE:FF, SSID = ESAE_Network, s = random per run")

    if failed_or_skipped:
        print(f"\n>>> Note: skipped {failed_or_skipped} aborted/failed random attempt(s); averages use {successful} successful runs.")

    ct1 = proto.print_timings(
        "Client Round 1 Average Timings (Commit)",
        average_timings(c1_acc, successful),
    )
    st1 = proto.print_timings(
        "Server Round 1 Average Timings (Commit + Key Derivation)",
        average_timings(s1_acc, successful),
    )
    ct2 = proto.print_timings(
        "Client Round 2 Average Timings (Key Derivation + Con_C)",
        average_timings(c2_acc, successful),
    )
    st2 = proto.print_timings(
        "Server Round 2 Average Timings (Verify Con_C + Con_S)",
        average_timings(s2_acc, successful),
    )
    ct3 = proto.print_timings(
        "Client Round 3 Average Timings (Verify Con_S)",
        average_timings(c3_acc, successful),
    )

    client_total = ct1 + ct2 + ct3
    server_total = st1 + st2

    print(f"\n{'=' * 72}")
    print("  AVERAGE SUMMARY")
    print(f"{'=' * 72}")
    print(f"  Average initialization time:       {t_init_avg * 1000:>10.6f} ms")
    print(f"  Client average computation time:   {client_total * 1000:>10.6f} ms")
    print(f"  Server average computation time:   {server_total * 1000:>10.6f} ms")
    print(f"  Combined average total:            {(client_total + server_total) * 1000:>10.6f} ms")
    print(f"  Combined average incl. init:       {(t_init_avg + client_total + server_total) * 1000:>10.6f} ms")
    print(f"{'=' * 72}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Benchmark AsymSAE_protocol_updated.py over multiple curves and print average timings."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1000,
        help="Number of successful protocol executions per curve. Default: 1000.",
    )
    parser.add_argument(
        "--curves",
        nargs="+",
        choices=list(CURVES.keys()),
        default=list(CURVES.keys()),
        help="Curves to benchmark. Default: all four required curves.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.runs <= 0:
        raise ValueError("--runs must be a positive integer.")

    for curve_name in args.curves:
        benchmark_curve(curve_name, CURVES[curve_name], args.runs)


if __name__ == "__main__":
    main()
