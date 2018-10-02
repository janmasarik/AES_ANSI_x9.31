# ANSI X9.31 PRNG based on AES 128-bit

Implementation based on [NIST Specification](https://web.archive.org/web/20140813123026/http://csrc.nist.gov/groups/STM/cavp/documents/rng/931rngext.pdf).

Uses insecure ECB mode and even though it passes tests from NIST STS, it obviously shouldn't be used for any serious purposes. 

### Usage
```bash
$ pipenv install
$ pipenv run python prng.py --out /tmp/k.bin --size 1337 --seed 1111111111111111 --key 2222222222222222
```
