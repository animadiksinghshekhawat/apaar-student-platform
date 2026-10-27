"""Pure-Python anomaly detection: Isolation Forest plus robust z-scores for plain-language reasons."""
import math, random, statistics

FLOOR = [0.08, 0.04, 0.5, 0.10]  # smallest deviation treated as meaningful per feature
FEATURES = ["enrolment vs approved intake", "quota-seat share", "open flags per 100 students", "year-on-year growth"]


def _c(n):
    return 0.0 if n <= 1 else 2 * (math.log(n - 1) + 0.5772156649) - 2 * (n - 1) / n


def _build(X, depth, limit, rng):
    if depth >= limit or len(X) <= 1:
        return ("leaf", len(X))
    q = rng.randrange(len(X[0]))
    lo, hi = min(x[q] for x in X), max(x[q] for x in X)
    if lo == hi:
        return ("leaf", len(X))
    p = rng.uniform(lo, hi)
    return ("node", q, p, _build([x for x in X if x[q] < p], depth + 1, limit, rng),
            _build([x for x in X if x[q] >= p], depth + 1, limit, rng))


def _path(x, t, d=0):
    if t[0] == "leaf":
        return d + _c(t[1])
    return _path(x, t[3] if x[t[1]] < t[2] else t[4], d + 1)


def isolation_scores(X, trees=100, seed=1):
    """Returns anomaly score in 0..1 per row (about 0.5 = normal, towards 1 = easy to isolate)."""
    n = len(X)
    if n < 4:
        return [0.5] * n
    cols = list(zip(*X))
    scale = [(min(c), (max(c) - min(c)) or 1.0) for c in cols]
    Z = [[(v - scale[j][0]) / scale[j][1] for j, v in enumerate(row)] for row in X]
    rng, limit = random.Random(seed), math.ceil(math.log2(n))
    forest = [_build([Z[i] for i in rng.sample(range(n), min(n, 256))], 0, limit, rng) for _ in range(trees)]
    return [2 ** (-(sum(_path(z, t) for t in forest) / trees) / _c(n)) for z in Z]


def analyze(X, names=FEATURES):
    """For each row: (score 0..100, reasons). Reasons are upward deviations from the peer median (robust z > 2)."""
    n = len(X)
    iso = isolation_scores(X)
    cols = list(zip(*X)) if n else []
    stats = []
    for j, c in enumerate(cols):
        med = statistics.median(c)
        mad = statistics.median([abs(v - med) for v in c]) * 1.4826
        stats.append((med, max(mad, FLOOR[j])))
    out = []
    for i, row in enumerate(X):
        reasons, zmax = [], 0.0
        for j, v in enumerate(row):
            z = (v - stats[j][0]) / stats[j][1]
            if z > 2.0 and v - stats[j][0] > 0.05:
                reasons.append(f"{names[j]} is {v:.2f} versus peer median {stats[j][0]:.2f}")
            zmax = max(zmax, z)
        base = max(0.0, (iso[i] - 0.5) / 0.25) * 100
        out.append((min(100, round(max(base, min(100, zmax * 10) if reasons else 0))), reasons))
    return out
