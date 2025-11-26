# K!nd4SUS CTF 2025

## Matrices Matrices Matrices

### Solution
The challenge revolves around the Learning With Error problem, having only the public key $(A, b)$. The elements of the public key are linked by the relation:

$$A \times s + e = b$$

Given $m=70$ and $n=30$, $A$ is the $m \times n$ public matrix, $s$ the $n \times 1$ secret vector, $e$ the $m \times 1$ error vector and $b$ the $n \times 1$ public vector. The idea is to represent the cryptosystem through a lattice and recover the error vector $e$ solving the SVP (Shortest Vector Problem) with a reduction of the lattice. So we can rewrite the initial relation as:

$$
\begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s \\
-1
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

The vector $(-e, -t)$ belongs to the lattice with basis $\begin{pmatrix} A&b\\ 0&t \end{pmatrix}$, since it can be written as a linear combination. We can perform a gaussian elimination on the columns of A to find an invertible matrix $U$ such that:

$$AU = \begin{pmatrix}
I_{n \times n} \\
A'
\end{pmatrix}$$

This means that we can rewrite the previous multiplication as:
$$
\begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s \\
-1 
\end{pmatrix}
= \begin{pmatrix}
A & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
U & 0 \\
0 & 1 
\end{pmatrix}
\begin{pmatrix}
U^{-1} & 0 \\
0 & 1
\end{pmatrix}
\begin{pmatrix}
s \\
-1
\end{pmatrix}
= \begin{pmatrix}
\begin{pmatrix}
I_n \\
A'
\end{pmatrix} & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s' \\
-1
\end{pmatrix}
$$

So the problem now becomes finding a $s'$ such that the following equation it's true:

$$
\begin{pmatrix}
\begin{pmatrix}
I_n \\
A'
\end{pmatrix} & b \\
0 & t
\end{pmatrix}
\begin{pmatrix}
s' \\
-1
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

The matrices are considered over $\mathbb{Z}_{271}$, but since we are working with a lattice now, we have to turn this in an identity of matrices over $\mathbb{Z}$, which basically means adding to the equation that defines $e$ a vector of coordinates that are a multiple of $q=271$:

$$
-e = \begin{pmatrix}
I_n \\
A'
\end{pmatrix}
s' - b + \begin{pmatrix}
0_n \\
q I_{m-n} k
\end{pmatrix}
$$

Given this equation and the previous one, we can define the following matrix $B$

$$
B = \begin{pmatrix}
\begin{pmatrix}
I_{n} \\
A'
\end{pmatrix} & b & \begin{pmatrix}
0_n \\
q I_{m-n}
\end{pmatrix} \\
0 & t & 0
\end{pmatrix}
$$

Now we have just to find the shortest vector of the lattice defined by the columns of $B$. If there are no other significantly short vectors in the lattice, we will find a vector in the form $\begin{pmatrix} -e, -t \end{pmatrix}$ or $\begin{pmatrix} e, t \end{pmatrix}$, obtained from a linear combination with $B$:

$$
B \begin{pmatrix}
s' \\
-1 \\
k
\end{pmatrix}
= \begin{pmatrix}
-e \\
-t
\end{pmatrix}
$$

Once we have obtained $e$, we can simply retrieve $s$ by subtracting $e$ from $b$ and then solving the system of equations system.

### Exploit
The solution explained is achieved using sage, building directly $B$ calculating the Reduced Row Echelon Form on the transposition of A and then transpositioning again to obtain $\begin{pmatrix} I_n \\ A' \end{pmatrix}$ and using $t=1$. Then the shortest vector of the lattice defined by the columns of $B$ is obtained applying Lenstra-Lenstra-Lovàsz on transposed $B$, getting $(e,t)$ as the first row of the reduced matrix.

```python
from sage.all import GF, identity_matrix, Matrix, ZZ

q = 271
qf = GF(q)
m = 70
n = 30

def retrieve_s(A, b):
    left = A.transpose().rref().transpose()
    zero_vector = Matrix(qf, [[0 for _ in range(n)]])
    left = left.stack(zero_vector)
    
    middle = b.stack(Matrix(qf, [[1]]))
    
    zero_matrix = Matrix(ZZ, [[0 for _ in range(m-n)] for _ in range(n)])
    q_identity_matrix = q*identity_matrix(ZZ, m - n)
    zero_vector = Matrix(ZZ, [[0 for _ in range(m-n)]])
    right = zero_matrix.stack(q_identity_matrix).stack(zero_vector)

    B = left.augment(middle).change_ring(ZZ).augment(right)
    reduced = B.transpose().LLL()
    e = reduced[0][:-1]
    e = Matrix(qf, [[e[i]] for i in range(m)])

    a_times_s = b - e
    s = A.solve_right(a_times_s)
    return s

a=[...]
b=[...]

a = Matrix(qf, a)
b = Matrix(qf, b)
s = retrieve_s(a, b)
flag = [chr(x) for x in s.list()]
print("".join(flag))
```
