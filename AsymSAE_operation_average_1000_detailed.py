#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detailed primitive operation timing evaluation for AsymSAE_protocol_updated.py.

This script measures the average running time of:

    T_pm       : Point multiplication
    T_pa       : Point addition
    T_H2C      : Hash-to-curve function H2C
    T_H0       : Hash function H0
    T_H1       : Hash function H1

and all HMAC/KDF usages that appear in the AsymSAE protocol:

    T_HMAC_val
        HMAC(0^L, max(MAC_C,MAC_S) || min(MAC_C,MAC_S))

    T_HMAC_seed_C
        HMAC(0^L, [K_C]_x)

    T_HMAC_seed_S
        HMAC(0^L, [K_S]_x)

    T_HMAC_Con_C
        HMAC(kck_c, s1 || E1 || s2 || E2)

    T_HMAC_Verify_Con_C
        HMAC(kck_s, s1 || E1 || s2 || E2)

    T_HMAC_Con_S
        HMAC(kck_s, s2 || E2 || s1 || E1)

    T_HMAC_Verify_Con_S
        HMAC(kck_c, s2 || E2 || s1 || E1)

    T_KDF_C
        KDF(seed_C, s1, L+256)

    T_KDF_S
        KDF(seed_S, s1, L+256)

For each curve, every operation is executed 1000 times by default and the
average timing is printed in a format close to AsymSAE_protocol_updated.py.

Important measurement note:
    Inputs such as serialized messages, x-coordinate bytes, seed values, and
    KDF contexts are prepared before timing. The reported HMAC/KDF values are
    therefore the average time of the HMAC/KDF function calls themselves.

Curves:
    prime192v1, prime256v1, secp192k1, secp256k1

Usage:
    Put this file in the same directory as AsymSAE_protocol_updated.py, then run:

        python3 AsymSAE_operation_average_1000_detailed.py

Optional:
        python3 AsymSAE_operation_average_1000_detailed.py --runs 1000
        python3 AsymSAE_operation_average_1000_detailed.py --curves prime192v1 secp256k1
"""

import argparse
import os
import sys
import time
from collections import OrderedDict

from charm.toolbox.ecgroup import ECGroup, ZR
from charm.toolbox.eccurve import prime192v1, prime256v1, secp192k1, secp256k1

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


def configure_curve(curve_obj):
    """Reconfigure AsymSAE_protocol_updated.py to use the target curve."""
    proto.group = ECGroup(curve_obj)
    proto.p = proto.group.order()

    # Keep the same security parameter and output layout as the original file.
    proto.L_BITS = 256
    proto.L_BYTES = proto.L_BITS // 8
    proto.ZERO_KEY = b"\x00" * proto.L_BYTES


def timed_average(func, inputs):
    """
    Execute func on all prepared inputs and return the average elapsed time.
    Input preparation is intentionally excluded from the measurement.
    """
    total = 0.0
    for args in inputs:
        start = time.perf_counter()
        func(*args)
        end = time.perf_counter()
        total += end - start
    return total / len(inputs)


def print_operation_timings(title, timings):
    """Print average timings in a style close to the original file."""
    print(f"\n{'=' * 72}")
    print(f"  {title}")
    print(f"{'=' * 72}")
    total = 0.0
    for label, elapsed in timings.items():
        print(f"  {label:<55s} {elapsed * 1000:>10.6f} ms")
        total += elapsed
    print(f"  {'─' * 70}")
    print(f"  {'TOTAL of listed average timings':<55s} {total * 1000:>10.6f} ms")
    return total


def prepare_inputs(runs):
    """
    Prepare protocol-like inputs for all operation tests.

    Preparation time is not included in the final reported averages.
    """
    MAC_C = "00:11:22:33:44:55"
    MAC_S = "AA:BB:CC:DD:EE:FF"
    SSID = "ESAE_Network"
    pw = "my_secret_password"

    mac_c_b = MAC_C.encode("utf-8")
    mac_s_b = MAC_S.encode("utf-8")
    val_msg = max(mac_c_b, mac_s_b) + min(mac_c_b, mac_s_b)

    h0_inputs = []
    h2c_inputs = []
    h1_inputs = []
    pm_inputs = []
    pa_inputs = []

    hmac_val_inputs = []
    hmac_seed_c_inputs = []
    hmac_seed_s_inputs = []
    hmac_con_c_inputs = []
    hmac_verify_con_c_inputs = []
    hmac_con_s_inputs = []
    hmac_verify_con_s_inputs = []

    kdf_c_inputs = []
    kdf_s_inputs = []

    for _ in range(runs):
        salt = os.urandom(16).hex()

        h0_inputs.append((pw, SSID, salt))

        pi0, pi1 = proto.H0(pw, SSID, salt)
        V = proto.H2C(pi0, SSID) ** pi1

        val = proto.compute_val(MAC_C, MAC_S)
        base = proto.H2C(pi0, SSID)
        PE = base ** val

        r1 = proto.group.random(ZR)
        m1 = proto.group.random(ZR)
        r2 = proto.group.random(ZR)
        m2 = proto.group.random(ZR)

        s1 = r1 + m1
        s2 = r2 + m2
        E1 = PE ** (-m1)
        E2 = PE ** (-m2)

        c = proto.H1(E1, s1, E2, s2, pi0)

        Z_client = E2 * (PE ** s2)
        exp_client = r1 + (c * pi1)
        KC = Z_client ** exp_client

        base_server = E1 * (PE ** s1) * (V ** (c * val))
        KS = base_server ** r2

        seed_C = proto.HMAC(proto.ZERO_KEY, proto.point_x_bytes(KC))
        seed_S = proto.HMAC(proto.ZERO_KEY, proto.point_x_bytes(KS))

        ctx_s1 = proto.group.serialize(s1)
        kck_pmk_c = proto.KDF(seed_C, ctx_s1, proto.L_BITS + 256)
        kck_pmk_s = proto.KDF(seed_S, ctx_s1, proto.L_BITS + 256)
        kck_c = kck_pmk_c[:proto.L_BYTES]
        kck_s = kck_pmk_s[:proto.L_BYTES]

        msg_s1_e1_s2_e2 = (
            proto.group.serialize(s1)
            + proto.group.serialize(E1)
            + proto.group.serialize(s2)
            + proto.group.serialize(E2)
        )
        msg_s2_e2_s1_e1 = (
            proto.group.serialize(s2)
            + proto.group.serialize(E2)
            + proto.group.serialize(s1)
            + proto.group.serialize(E1)
        )

        # Basic primitive inputs.
        h2c_inputs.append((pi0, SSID))
        h1_inputs.append((E1, s1, E2, s2, pi0))
        pm_inputs.append((E1, r1))
        pa_inputs.append((E1, E2))

        # Detailed HMAC inputs. Messages are prepared outside the timing.
        hmac_val_inputs.append((proto.ZERO_KEY, val_msg))
        hmac_seed_c_inputs.append((proto.ZERO_KEY, proto.point_x_bytes(KC)))
        hmac_seed_s_inputs.append((proto.ZERO_KEY, proto.point_x_bytes(KS)))
        hmac_con_c_inputs.append((kck_c, msg_s1_e1_s2_e2))
        hmac_verify_con_c_inputs.append((kck_s, msg_s1_e1_s2_e2))
        hmac_con_s_inputs.append((kck_s, msg_s2_e2_s1_e1))
        hmac_verify_con_s_inputs.append((kck_c, msg_s2_e2_s1_e1))

        # Detailed KDF inputs. Seed and context are prepared outside the timing.
        kdf_c_inputs.append((seed_C, ctx_s1, proto.L_BITS + 256))
        kdf_s_inputs.append((seed_S, ctx_s1, proto.L_BITS + 256))

    return {
        "basic": {
            "pm": pm_inputs,
            "pa": pa_inputs,
            "h2c": h2c_inputs,
            "h0": h0_inputs,
            "h1": h1_inputs,
        },
        "hmac": {
            "val": hmac_val_inputs,
            "seed_c": hmac_seed_c_inputs,
            "seed_s": hmac_seed_s_inputs,
            "con_c": hmac_con_c_inputs,
            "verify_con_c": hmac_verify_con_c_inputs,
            "con_s": hmac_con_s_inputs,
            "verify_con_s": hmac_verify_con_s_inputs,
        },
        "kdf": {
            "client": kdf_c_inputs,
            "server": kdf_s_inputs,
        },
    }


def benchmark_curve(curve_name, curve_obj, runs):
    configure_curve(curve_obj)

    print("=" * 72)
    print("  AsymSAE Detailed Primitive Operation Timing Evaluation")
    print(f"  Curve: {curve_name}")
    print(f"  Runs per operation: {runs}")
    print("=" * 72)

    print("\n>>> Preparing protocol-like inputs")
    prep_start = time.perf_counter()
    inputs = prepare_inputs(runs)
    prep_elapsed = time.perf_counter() - prep_start
    print(f"      Input preparation completed in {prep_elapsed * 1000:.6f} ms")
    print("      Note: preparation time is NOT included in the operation averages.")
    print("      Note: serialized HMAC messages and KDF contexts are prepared before timing.")

    print("\n>>> Measuring primitive operations")

    basic_timings = OrderedDict()
    basic_timings["T_pm: Point multiplication P ** a"] = timed_average(
        lambda P, a: P ** a,
        inputs["basic"]["pm"],
    )
    basic_timings["T_pa: Point addition P * Q"] = timed_average(
        lambda P, Q: P * Q,
        inputs["basic"]["pa"],
    )
    basic_timings["T_H2C: H2C(π0|SSID)"] = timed_average(
        proto.H2C,
        inputs["basic"]["h2c"],
    )
    basic_timings["T_H0: H0(pw,SSID,s)"] = timed_average(
        proto.H0,
        inputs["basic"]["h0"],
    )
    basic_timings["T_H1: H1(E1,s1,E2,s2,π0)"] = timed_average(
        proto.H1,
        inputs["basic"]["h1"],
    )

    basic_total = print_operation_timings(
        "Average Basic Primitive Operation Timings",
        basic_timings,
    )

    hmac_timings = OrderedDict()
    hmac_timings["T_HMAC_val: HMAC(0^L,max(MAC_C,MAC_S)||min(MAC_C,MAC_S))"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["val"],
    )
    hmac_timings["T_HMAC_seed_C: HMAC(0^L,[K_C]_x)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["seed_c"],
    )
    hmac_timings["T_HMAC_seed_S: HMAC(0^L,[K_S]_x)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["seed_s"],
    )
    hmac_timings["T_HMAC_Con_C: HMAC(kck_c,s1|E1|s2|E2)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["con_c"],
    )
    hmac_timings["T_HMAC_Verify_Con_C: HMAC(kck_s,s1|E1|s2|E2)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["verify_con_c"],
    )
    hmac_timings["T_HMAC_Con_S: HMAC(kck_s,s2|E2|s1|E1)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["con_s"],
    )
    hmac_timings["T_HMAC_Verify_Con_S: HMAC(kck_c,s2|E2|s1|E1)"] = timed_average(
        proto.HMAC,
        inputs["hmac"]["verify_con_s"],
    )

    hmac_total = print_operation_timings(
        "Average Detailed HMAC Timings in AsymSAE",
        hmac_timings,
    )

    kdf_timings = OrderedDict()
    kdf_timings["T_KDF_C: KDF(seed_C,s1,L+256)"] = timed_average(
        proto.KDF,
        inputs["kdf"]["client"],
    )
    kdf_timings["T_KDF_S: KDF(seed_S,s1,L+256)"] = timed_average(
        proto.KDF,
        inputs["kdf"]["server"],
    )

    kdf_total = print_operation_timings(
        "Average Detailed KDF Timings in AsymSAE",
        kdf_timings,
    )

    print(f"\n{'=' * 72}")
    print("  AVERAGE SUMMARY")
    print(f"{'=' * 72}")
    print(f"  Curve:                              {curve_name}")
    print(f"  Runs per operation:                 {runs}")
    print(f"  Sum of basic average operations:    {basic_total * 1000:>10.6f} ms")
    print(f"  Sum of detailed HMAC averages:      {hmac_total * 1000:>10.6f} ms")
    print(f"  Sum of detailed KDF averages:       {kdf_total * 1000:>10.6f} ms")
    print(f"  Sum of all listed average timings:  {(basic_total + hmac_total + kdf_total) * 1000:>10.6f} ms")
    print(f"{'=' * 72}\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate detailed primitive-operation timings for AsymSAE."
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1000,
        help="Number of executions per operation per curve. Default: 1000.",
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
