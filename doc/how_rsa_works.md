# How Does RSA work?
## Introduction
In the physical world, no one had ever conceived of a lock requiring two keys until Diffie and Hellman introduced the idea of public key cryptography [1]. However, they didn’t propose a practical implementation. It was Rivest, Shamir, and Adleman who, for the first time, devised a functional system to implement this concept [2], revolutionizing cryptography with what we now call RSA.

The RSA magic works as follows:

Given a message \( M \):

- $ C \equiv (E(M)) \equiv M^e \mod n$
- $ M \equiv (D(C)) \equiv C^d \mod n$

where:

$e$ is the public exponent,

$d$ is the private exponent,

$n$ is the modulus.

## Modular Arithmetic and Congruence

The symbol $\equiv$ represents congruence in mathematics, meaning two numbers have the same remainder when divided by a given modulus. For example,

$17 \equiv 5 \mod 12$

Here, 17 and 5 have the same remainder, 5 when divided by 12.

## The RSA process
Applying each of the RSA keys (encryption and decryption) returns the origin message:

$$
D(E(M)) \equiv D(M^e \mod n) \equiv (M^e)^d \mod n \equiv M^{e \cdot d} \mod n \tag{1}
$$

The product $e \cdot d$ is carefully chosen during RSA key selection:

$$
e \cdot d \equiv 1 \mod \phi(n) \tag{2}
$$

Here, $\phi(n)$ is the Euler's totient function, which gives the count of integers less than n that are relatively prime to n. Specifically, for any $k$ where $ 0 < k < n$, $gcd(k, n)=1$.

If two numbers are congruent:
$$
a \equiv b \mod m
$$
This implies $a - b$ is divisible by m, meaning:
$$
a - b = mk
$$
Thus, we can express a as: 
$$
a = b + mk
$$
Using this, equation (2) becomes:
$$
e \cdot d = 1 + \phi(n) \cdot k \tag{3}
$$
From this, we can further deduce:
$$
M^{e \cdot d} = M^{1 + \phi(n) \cdot k} = M \cdot (M^{\phi(n))^{k}}) \tag{4}
$$

## Euler's Theorem
Euler's totient function is critical to RSA security. Another key pillar is Euler's Theorem, which states:
$$
M^{\phi(n)} \equiv 1 \mod n \tag{5}
$$
This holds if $M$ is relatively prime to $n$ (i.e., $gcd(M, n)=1$).

Using Euler's Theorem, we can simplify:
$$
M^{e \cdot d} \equiv M \cdot 1^{k} \equiv M \mod n \tag{6}
$$

## V. Key Generation

We have shown that RSA works based on Euler's theorem. But how are the keys, $(e, n)$ and $(d, n)$ generated? 

The relationship between $e$ and $d$ is governed by the equation:

$$
e \cdot d \equiv 1 \mod \phi(n)
$$

For this equation to hold, $e$ must be relatively prime to $\phi(n)$.

while $n$ can be any number, for RSA, it must satisfy certain conditions to ensure security. Specifically, the modulus $n$ must be chosen so that $M$ is relatively prime to $n$. A prime $n$ would trivially meet this requirement, however, if $n$ were prime,  its Euler's totient function would be:

$$
\phi(n) = n - 1
$$

This would reveal $\phi(n)$ too easily. Instead, RSA selects two large prime numbers:
$$
n = p \cdot q
$$

$$
\phi(n) = (p - 1) \cdot (q - 1)
$$

This makes factoring  $n$ difficult and, in turn, guessing $\phi(n)$ becomes puzzling --an essential aspect of RSA's security while reckoning $\phi(n)$ during key selection remains plain.

Once $n$ is chosen, finding $d$, the private exponent, is straightforward using equation $(2)$.

## Ensuring Secure Messages
In addition to the choice of $n$, we also want the messages less then the modulus such that we assure the Euler's Theorem.

## EXamples
Below are some examples demonstrating the RSA process in action: 

```console
$ cd app/demo_rsa_keys
$ ./demo_rsa_keys 
Pick the first prime number: 3
Pick the second prime number: 11
p = 3, q = 11
Public Key: (13, 33)
Private Key: (17, 33)
$ cd ../demo_rsa_trapdoor 
$ ./demo_rsa_trapdoor 
Usage: ./demo_rsa_trapdoor -m <message> -k <key> -n <modulus>
Note: All arguments (-m, -k, -n) must be non-zero.
$ ./demo_rsa_trapdoor -m 5 -k 13 -n 33
Result: 26
$ ./demo_rsa_trapdoor -m 26 -k 17 -n 33 
Result: 5
$ 
$ ./demo_rsa_trapdoor -m 35 -k 17 -n 33
Error: Message must be strictly less than the modulus.
$ ./demo_rsa_trapdoor -m 31 -k 17 -n 33
Result: 4
$ ./demo_rsa_trapdoor -m 4 -k 13 -n 33
Result: 31
$
```

## References

1. Diffie, W., & Hellman, M. E. (1976). New directions in cryptography. *IEEE Transactions on Information Theory*, 22(6), 644–654. https://doi.org/10.1109/TIT.1976.1055638
2. Rivest, R. L., Shamir, A., & Adleman, L. (1978). A method for obtaining digital signatures and public-key cryptosystems. *Communications of the ACM*, 21(2), 120–126. https://doi.org/10.1145/359340.359342




