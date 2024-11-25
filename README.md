# BHJL13&LMS-based HSS: easy demo

a 2-server 3-degree HSS scheme constructed by LMS frame using BHJL13 as the underlying linear HE ($f(x,y,z)=xyz$)

> an easy example of LMS

### Setup

#### Requirements

- `gcc`
- `make`
- `cmake`
- `gmp`
- `pbc`

##### GNU Multi Precision

```shell
 sudo apt install libgmp-dev
```

##### PBC

Downlaod `pbclib` from [here](https://crypto.stanford.edu/pbc/download.html)

```shell
sudo apt install flex nettle-dev bison byacc
cd pbc-x.x.x
./configure
make -j9
make install
sudo ldconfig -v
```

### Build

```shell
mkdir build
cd build
cmake ..
make -j9
```

### Run

#### Tests

```shell
cd build
./2k-prs-test
```

#### Demo

```shell
cd build
./2k-prs-demo
```

### Clean

```shell
rm -rf build/
```
