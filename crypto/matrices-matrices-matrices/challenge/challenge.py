from sage.all import GF, Matrix
import os, random

assert("FLAG" in os.environ)
FLAG = os.environ["FLAG"]
assert(FLAG.startswith("KSUS{") and FLAG.endswith("}"))

q = 271
qf = GF(q)
m = 70
n = 30

def key_gen():
    a = Matrix(qf, [[qf.random_element() for _ in range(n)] for _ in range(m)])
    s = Matrix(qf, [[ord(c)] for c in FLAG])
    e = Matrix(qf, [[int(round(random.gauss(0, 2/3)))] for _ in range(m)])
    b = a * s + e
    return s, (a,b)

sk, pk = key_gen()
a, b = pk

print(f"a={[list(a[i]) for i in range(m)]}")
print(f"b={[list(b[i]) for i in range(m)]}")