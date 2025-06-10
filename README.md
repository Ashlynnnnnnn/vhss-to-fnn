# VHSS-to-FNN

Using verifiable homomorphic secret sharing to ensure privacy and correctness of inference tasks in feedforward neural networks

> Demo: an MLP to classify images from the MNIST database (hand-written digit database)

## Setup

### Requirements

- `gcc`
- `make`
- `cmake`
- `gmp`
- `pbc`

#### GNU Multi Precision

```shell
 sudo apt install libgmp-dev
```

#### PBC

Downlaod `pbclib` from [here](https://crypto.stanford.edu/pbc/download.html)

```shell
sudo apt install flex nettle-dev bison byacc
cd pbc-x.x.x
./configure
make -j9
make install
sudo ldconfig -v
```

## Build

```shell
mkdir build
cd build
cmake ..
make -j9
```

## Run

### LMS18 Demo

```shell
cd build
./2k-prs-demo
```

### Original Model

```shell
cd build
./original
```

### Model with Approximation

```shell
cd build
./fnn
```

### Model with Approximation and "linear privacy and verifiability"

```shell
cd build
./linear-vhss-to-fnn
```

### Whole Process

```shell
cd build
./vhss-to-fnn
```

### Clean

```shell
rm -rf build/
```
