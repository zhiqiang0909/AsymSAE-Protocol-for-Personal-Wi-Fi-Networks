"""
AsymSAE Protocol Implementation (asymmetric SAE-style, per updated protocol)
Using charm-crypto library with detailed CPU timing via time.perf_counter()

charm-crypto ECGroup 使用乘法群记法:
  - 标量乘法 k·P  →  P ** k
  - 点加法   P+Q  →  P * Q
  - 标量加法 a+b  →  a + b      (ZR 元素直接支持)
  - 标量乘法 a*b  →  a * b      (ZR 元素之间)
  - 标量求逆 a^-1 →  a ** -1

Protocol implemented here:

  Initialization:
    (π0, π1) = H0(pw, SSID, s)
    V = π1 · H2C(π0|SSID)
    AP stores (π0, V, SSID, s); STA only remembers pw.

  Active scanning:
    STA → AP: MAC_C
    AP  → STA: MAC_S, SSID, s

  SAE commit exchange:
    val = HMAC(0^L, max(MAC_C,MAC_S) | min(MAC_C,MAC_S)) mod (p-1) + 1
    PE  = val · H2C(π0|SSID)

    STA samples r1,m1, computes s1=r1+m1 mod p and E1=-m1·PE,
    then sends (MAC_C,E1,s1). AP validates (E1,s1), samples r2,m2,
    computes s2=r2+m2 mod p and E2=-m2·PE, then sends (E2,s2).

    Both compute c = H1(E1,s1,E2,s2,π0).
    STA computes K_C = (r1 + c·π1)(E2 + s2·PE).
    AP  computes K_S = r2(E1 + s1·PE + c·val·V).

  SAE key confirmation:
    seed_C = HMAC(0^L, [K_C]_x), seed_S = HMAC(0^L, [K_S]_x)
    kck|pmk = KDF(seed, s1, L+256)
    Con_C = HMAC(kck_c, s1|E1|s2|E2|)
    Con_S = HMAC(kck_s, s2|E2|s1|E1|)

Correctness:
   E2 + s2·PE = -m2·PE + (r2+m2)·PE = r2·PE
   E1 + s1·PE = -m1·PE + (r1+m1)·PE = r1·PE
   K_C = (r1+c·π1)·r2·val·H2C(π0|SSID)
   K_S = r2·(r1·val·H2C(π0|SSID) + c·val·π1·H2C(π0|SSID))
       = r2·val·(r1+c·π1)·H2C(π0|SSID) = K_C
"""

from charm.toolbox.ecgroup import ECGroup, ZR, G
from charm.toolbox.eccurve import secp256k1
import hashlib
import hmac as hmac_lib
import os
import time


# ============================================================
# Global Setup
# ============================================================
group   = ECGroup(secp256k1)
p       = group.order()
L_BITS  = 256
L_BYTES = L_BITS // 8
ZERO_KEY = b'\x00' * L_BYTES        # 0^L


# ============================================================
# Hash & MAC Functions
# ============================================================

def H0(pw, SSID, s):
    """
    H0 : {0,1}* -> Z*p × Z*p
    Maps (pw, SSID, salt) to two independent scalars (π0, π1).
    """
    data = "{}||{}||{}".format(pw, SSID, s).encode('utf-8')
    h0 = hashlib.sha256(data + b'\x00').digest()
    pi0_int = int.from_bytes(h0, 'big') % (int(p) - 1) + 1
    pi0 = group.init(ZR, pi0_int)
    h1 = hashlib.sha256(data + b'\x01').digest()
    pi1_int = int.from_bytes(h1, 'big') % (int(p) - 1) + 1
    pi1 = group.init(ZR, pi1_int)
    return pi0, pi1


def _to_bytes(value):
    """Serialize protocol objects for transcript hashing/MAC input."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode('utf-8')
    return group.serialize(value)


def H2C(pi0, SSID):
    """H2C(π0|SSID) : Z*p × {0,1}* -> G minus the point at infinity."""
    data = group.serialize(pi0) + b"||" + SSID.encode('utf-8')
    return group.hash(data, G)


def H1(*args):
    """
    H1 : {0,1}* -> Z*p.
    Used as c = H1(E1, s1, E2, s2, π0) in the updated protocol.
    """
    digest = hashlib.sha256(b"||".join(_to_bytes(a) for a in args)).digest()
    c_int = int.from_bytes(digest, 'big') % (int(p) - 1) + 1
    return group.init(ZR, c_int)


def point_x_bytes(P):
    """
    Return bytes used for [P]_x in seed = HMAC(0^L, [P]_x).

    charm-crypto does not expose a stable public x-coordinate accessor across
    all EC backends. For standard SEC1 encodings, extract x. If the backend
    uses a different serialization, fall back to the serialized group element;
    this keeps both parties deterministic while preserving the timing flow.
    """
    enc = group.serialize(P)
    if isinstance(enc, str):
        enc = enc.encode('utf-8')
    coord_len = (int(p).bit_length() + 7) // 8

    # SEC1 compressed form: 02/03 || x
    if len(enc) == 1 + coord_len and enc[0] in (2, 3):
        return enc[1:]

    # SEC1 uncompressed form: 04 || x || y
    if len(enc) == 1 + 2 * coord_len and enc[0] == 4:
        return enc[1:1 + coord_len]

    # Backend-specific fallback.
    return enc

def HMAC(key, msg):
    """HMAC-SHA256 → 32 bytes."""
    return hmac_lib.new(key, msg, hashlib.sha256).digest()


def KDF(seed, ctx_bytes, length_bits):
    """
    KDF based on iterated HMAC-SHA256 (HKDF-Expand-style).
    Output: length_bits bits.
    """
    out = b''
    counter = 1
    while len(out) * 8 < length_bits:
        block = HMAC(seed, ctx_bytes + counter.to_bytes(4, 'big'))
        out += block
        counter += 1
    return out[:length_bits // 8]


def compute_val(MAC_C, MAC_S):
    """
    val = HMAC(0^L, max(MAC_C,MAC_S) || min(MAC_C,MAC_S))
    val = val mod (q-1) + 1   →   val ∈ [1, q-1]
    """
    mac_c_b = MAC_C.encode('utf-8')
    mac_s_b = MAC_S.encode('utf-8')
    msg = max(mac_c_b, mac_s_b) + min(mac_c_b, mac_s_b)
    val_bytes = HMAC(ZERO_KEY, msg)
    val_int = int.from_bytes(val_bytes, 'big') % (int(p) - 1) + 1
    return group.init(ZR, val_int)


# ============================================================
# Timing Utility
# ============================================================

def timed(label, func, *args, **kwargs):
    """Execute func(*args) and return (result, elapsed_seconds)."""
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    return result, (end - start)


# ============================================================
# Initialization Phase (offline, one-time)
# ============================================================

def initialization(pw, SSID, s):
    """
    Offline initialization (Initialization Phase, lines 1–3):
      (π0, π1) = H0(pw, SSID, s)
      V        = π1 · H2C(π0|SSID)
    AP stores (π0, V, SSID, s).
    """
    pi0, pi1 = H0(pw, SSID, s)
    V = H2C(pi0, SSID) ** pi1
    return pi0, V


# ============================================================
# Client Side  (STA)
# ============================================================

def client_round1(pw, SSID, s, MAC_C, MAC_S):
    """
    Client Round 1 (Commit Exchange, client-side lines 3–10):
      compute (π0, π1), val, PE, r1, m1, s1, E1; send (MAC_C, E1, s1).
    """
    timings = {}

    (pi0, pi1), t = timed("H0", H0, pw, SSID, s)
    timings["(π0,π1) = H0(pw,SSID,s)"] = t

    val, t = timed("val", compute_val, MAC_C, MAC_S)
    timings["val = HMAC(0^L,max||min) mod(q-1)+1"] = t

    def compute_PE():
        return H2C(pi0, SSID) ** val
    PE, t = timed("PE", compute_PE)
    timings["PE = val·H2C(π0|SSID)"] = t

    r1, t = timed("r1", group.random, ZR)
    timings["r1 ←R Z*p"] = t

    m1, t = timed("m1", group.random, ZR)
    timings["m1 ←R Z*p"] = t

    s1, t = timed("s1", lambda: r1 + m1)
    timings["s1 = r1+m1 mod p"] = t

    E1, t = timed("E1", lambda: PE ** (-m1))
    timings["E1 = -m1·PE"] = t

    state = {
        "pi0": pi0, "pi1": pi1, "val": val, "PE": PE,
        "r1": r1,   "m1": m1,   "s1": s1, "E1": E1,
        "MAC_C": MAC_C, "MAC_S": MAC_S, "SSID": SSID, "salt": s,
    }
    msg = {"MAC_C": MAC_C, "E1": E1, "s1": s1}
    return state, msg, timings


def client_round2(state, server_msg):
    """
    Client Round 2 (Commit processing + STA confirmation):
      Validate (E2, s2); compute c; compute K_C=(r1+c·π1)(E2+s2·PE);
      derive seed_C, kck_c|pmk_c; send Con_C.

    The STA does not accept pmk_c until client_round3 verifies Con_S.
    """
    timings = {}

    E2, s2 = server_msg["E2"], server_msg["s2"]
    pi0, pi1, r1 = state["pi0"], state["pi1"], state["r1"]
    s1, E1, PE = state["s1"], state["E1"], state["PE"]

    ZR_zero = group.init(ZR, 0)
    ZR_one  = group.init(ZR, 1)
    O_G     = PE ** ZR_zero          # identity element of G

    def drop_check():
        return (E2 == E1) or (s2 == s1)
    drop, t = timed("drop", drop_check)
    timings["Drop if E2=E1 ∨ s2=s1"] = t
    if drop:
        raise Exception("Client: Drop and wait — duplicate/reflected commit!")

    def abort_validity():
        if s2 == ZR_zero or s2 == ZR_one:
            return True
        if E2 == O_G:
            return True
        return False
    av, t = timed("abort_validity", abort_validity)
    timings["Abort if s2∈{0,1} ∨ E2=O"] = t
    if av:
        raise Exception("Client: Abort — invalid server commit!")

    c, t = timed("c", H1, E1, s1, E2, s2, pi0)
    timings["c = H1(E1,s1,E2,s2,π0)"] = t

    def compute_KC():
        Z = E2 * (PE ** s2)
        exp = r1 + (c * pi1)
        return Z ** exp
    KC, t = timed("KC", compute_KC)
    timings["K_C = (r1+c·π1)(E2+s2·PE)"] = t

    def abort_KC():
        return KC == O_G
    ak, t = timed("abort_KC", abort_KC)
    timings["Abort if K_C=O"] = t
    if ak:
        raise Exception("Client: Abort — K_C is point at infinity!")

    seed_C, t = timed("seed_C", HMAC, ZERO_KEY, point_x_bytes(KC))
    timings["seed_C = HMAC(0^L, [K_C]_x)"] = t

    def compute_kdf():
        return KDF(seed_C, group.serialize(s1), L_BITS + 256)
    kck_pmk, t = timed("kdf", compute_kdf)
    timings["kck_c|pmk_c = KDF(seed_C, s1, L+256)"] = t
    kck_c = kck_pmk[:L_BYTES]
    pmk_c = kck_pmk[L_BYTES:]

    def compute_ConC():
        msg = group.serialize(s1) + group.serialize(E1) + group.serialize(s2) + group.serialize(E2)
        return HMAC(kck_c, msg)
    Con_C, t = timed("Con_C", compute_ConC)
    timings["Con_C = HMAC(kck_c, s1|E1|s2|E2)"] = t

    state.update({
        "E2": E2, "s2": s2,
        "c": c, "KC": KC,
        "seed_C": seed_C,
        "kck_c": kck_c, "pmk_c": pmk_c,
        "Con_C": Con_C,
    })
    return state, {"Con_C": Con_C}, timings


def client_round3(state, server_msg2):
    """
    Client Round 3 (STA verifies AP confirmation):
      Verify Con_S = HMAC(kck_c, s2|E2|s1|E1|); accept pmk_c.
    """
    timings = {}
    Con_S = server_msg2["Con_S"]
    kck_c = state["kck_c"]
    s1, E1, s2, E2 = state["s1"], state["E1"], state["s2"], state["E2"]

    def verify_ConS():
        msg = group.serialize(s2) + group.serialize(E2) + group.serialize(s1) + group.serialize(E1)
        return HMAC(kck_c, msg) == Con_S
    ok, t = timed("verify_ConS", verify_ConS)
    timings["Verify Con_S =? HMAC(kck_c, s2|E2|s1|E1)"] = t
    if not ok:
        raise Exception("Client: Drop — Con_S verification failed!")

    return state["pmk_c"], timings


# ============================================================
# Server Side  (AP)
# ============================================================

def server_round1(pi0_stored, V_stored, SSID, s, MAC_C, MAC_S, client_msg):
    """
    Server Round 1 (AP commit processing):
      Validate (E1, s1); compute val, PE, r2, m2, s2, E2;
      compute c; compute K_S=r2(E1+s1·PE+c·val·V);
      derive seed_S, kck_s|pmk_s; send only (E2, s2).
    """
    timings = {}

    E1 = client_msg["E1"]
    s1 = client_msg["s1"]

    ZR_zero = group.init(ZR, 0)
    ZR_one  = group.init(ZR, 1)

    def abort_E1():
        if s1 == ZR_zero or s1 == ZR_one:
            return True
        O_G = H2C(pi0_stored, SSID) ** ZR_zero
        return E1 == O_G
    av, t = timed("abort_E1", abort_E1)
    timings["Abort if s1∈{0,1} ∨ E1=O"] = t
    if av:
        raise Exception("Server: Abort — invalid client commit!")

    val, t = timed("val", compute_val, MAC_C, MAC_S)
    timings["val = HMAC(0^L,max||min) mod(q-1)+1"] = t

    def compute_PE():
        return H2C(pi0_stored, SSID) ** val
    PE, t = timed("PE", compute_PE)
    timings["PE = val·H2C(π0|SSID)"] = t
    O_G = PE ** ZR_zero

    r2, t = timed("r2", group.random, ZR)
    timings["r2 ←R Z*p"] = t

    m2, t = timed("m2", group.random, ZR)
    timings["m2 ←R Z*p"] = t

    s2, t = timed("s2", lambda: r2 + m2)
    timings["s2 = r2+m2 mod p"] = t

    E2, t = timed("E2", lambda: PE ** (-m2))
    timings["E2 = -m2·PE"] = t

    c, t = timed("c", H1, E1, s1, E2, s2, pi0_stored)
    timings["c = H1(E1,s1,E2,s2,π0)"] = t

    def compute_KS():
        base = E1 * (PE ** s1) * (V_stored ** (c * val))
        return base ** r2
    KS, t = timed("KS", compute_KS)
    timings["K_S = r2(E1+s1·PE+c·val·V)"] = t

    def abort_KS():
        return KS == O_G
    ak, t = timed("abort_KS", abort_KS)
    timings["Abort if K_S=O"] = t
    if ak:
        raise Exception("Server: Abort — K_S is point at infinity!")

    seed_S, t = timed("seed_S", HMAC, ZERO_KEY, point_x_bytes(KS))
    timings["seed_S = HMAC(0^L, [K_S]_x)"] = t

    def compute_kdf():
        return KDF(seed_S, group.serialize(s1), L_BITS + 256)
    kck_pmk, t = timed("kdf", compute_kdf)
    timings["kck_s|pmk_s = KDF(seed_S, s1, L+256)"] = t
    kck_s = kck_pmk[:L_BYTES]
    pmk_s = kck_pmk[L_BYTES:]

    state = {
        "E1": E1, "s1": s1, "E2": E2, "s2": s2,
        "val": val, "PE": PE, "r2": r2, "m2": m2,
        "c": c, "KS": KS,
        "seed_S": seed_S,
        "kck_s": kck_s, "pmk_s": pmk_s,
    }
    msg = {"E2": E2, "s2": s2}
    return state, msg, timings


def server_round2(server_state, client_msg2):
    """
    Server Round 2 (AP verifies STA confirmation and sends AP confirmation):
      Verify Con_C = HMAC(kck_s, s1|E1|s2|E2|);
      send Con_S = HMAC(kck_s, s2|E2|s1|E1|); accept pmk_s.
    """
    timings = {}
    Con_C = client_msg2["Con_C"]
    kck_s = server_state["kck_s"]
    s1, E1, s2, E2 = server_state["s1"], server_state["E1"], server_state["s2"], server_state["E2"]

    def verify_ConC():
        msg = group.serialize(s1) + group.serialize(E1) + group.serialize(s2) + group.serialize(E2)
        return HMAC(kck_s, msg) == Con_C
    ok, t = timed("verify_ConC", verify_ConC)
    timings["Verify Con_C =? HMAC(kck_s, s1|E1|s2|E2)"] = t
    if not ok:
        raise Exception("Server: Drop — Con_C verification failed!")

    def compute_ConS():
        msg = group.serialize(s2) + group.serialize(E2) + group.serialize(s1) + group.serialize(E1)
        return HMAC(kck_s, msg)
    Con_S, t = timed("Con_S", compute_ConS)
    timings["Con_S = HMAC(kck_s, s2|E2|s1|E1)"] = t

    server_state["Con_S"] = Con_S
    return server_state["pmk_s"], {"Con_S": Con_S}, timings


# ============================================================
# Print Timings
# ============================================================

def print_timings(title, timings):
    print(f"\n{'='*72}")
    print(f"  {title}")
    print(f"{'='*72}")
    total = 0.0
    for label, elapsed in timings.items():
        print(f"  {label:<55s} {elapsed*1000:>10.6f} ms")
        total += elapsed
    print(f"  {'─'*70}")
    print(f"  {'TOTAL':<55s} {total*1000:>10.6f} ms")
    return total


# ============================================================
# Main
# ============================================================

def main():
    print("=" * 72)
    print("  AsymSAE Protocol Simulation (asymmetric SAE-style, charm-crypto)")
    print("  Curve: secp256k1")
    print("=" * 72)

    MAC_C = "00:11:22:33:44:55"
    MAC_S = "AA:BB:CC:DD:EE:FF"
    SSID  = "ESAE_Network"
    salt  = os.urandom(16).hex()
    pw    = "my_secret_password"

    print("\n>>> Initialization Phase (offline, one-time)")
    print(f"      SSID = {SSID}")
    print(f"      s    = {salt}")
    t0 = time.perf_counter()
    pi0_stored, V_stored = initialization(pw, SSID, salt)
    t_init = time.perf_counter() - t0
    print(f"      Initialization completed in {t_init*1000:.6f} ms")
    print(f"      AP stores (π0, V = π1·H2C(π0|SSID), SSID, s)")

    print("\n>>> Active Scanning")
    print(f"      STA → AP : MAC_C = {MAC_C}")
    print(f"      AP  → STA: MAC_S = {MAC_S}, SSID = {SSID}, s = {salt[:16]}...")

    print("\n>>> Client Round 1: send (MAC_C, E1, s1)")
    client_state, client_msg, c1_t = client_round1(
        pw, SSID, salt, MAC_C, MAC_S
    )

    print(">>> Server Round 1: recv (MAC_C, E1, s1) → send (E2, s2)")
    server_state, server_msg, s1_t = server_round1(
        pi0_stored, V_stored, SSID, salt, MAC_C, MAC_S, client_msg
    )

    print(">>> Client Round 2: recv (E2, s2) → send Con_C")
    client_state, client_msg2, c2_t = client_round2(client_state, server_msg)

    print(">>> Server Round 2: recv Con_C → send Con_S → accept pmk_s")
    pmk_s, server_msg2, s2_t = server_round2(server_state, client_msg2)

    print(">>> Client Round 3: recv Con_S → accept pmk_c")
    pmk_c, c3_t = client_round3(client_state, server_msg2)

    print(f"\n{'='*72}")
    print("  Session Key Verification")
    print(f"{'='*72}")
    print(f"  Client pmk_c = {pmk_c.hex()}")
    print(f"  Server pmk_s = {pmk_s.hex()}")
    if pmk_c == pmk_s:
        print("  ✓ Session keys MATCH — protocol succeeded!")
    else:
        print("  ✗ Session keys DO NOT match — protocol FAILED!")

    ct1 = print_timings("Client Round 1 Timings (Commit)",                 c1_t)
    st1 = print_timings("Server Round 1 Timings (Commit + Key Derivation)", s1_t)
    ct2 = print_timings("Client Round 2 Timings (Key Derivation + Con_C)",  c2_t)
    st2 = print_timings("Server Round 2 Timings (Verify Con_C + Con_S)",    s2_t)
    ct3 = print_timings("Client Round 3 Timings (Verify Con_S)",            c3_t)

    client_total = ct1 + ct2 + ct3
    server_total = st1 + st2

    print(f"\n{'='*72}")
    print(f"  SUMMARY")
    print(f"{'='*72}")
    print(f"  Client total computation time:  {client_total*1000:>10.6f} ms")
    print(f"  Server total computation time:  {server_total*1000:>10.6f} ms")
    print(f"  Combined total:                 {(client_total+server_total)*1000:>10.6f} ms")
    print(f"{'='*72}\n")


if __name__ == "__main__":
    main()
