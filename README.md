# libcsnark Compilation manual

- [libcsnark Compilation manual](#libcsnark-Compilation manual)
    - [Brief](#Brief)
    - [Compile](#Compile)
        - [Dependency](#Dependency)
        - [Compile libcsnark](#Compile libcsnark)

## Brief

Libcsnark adds some gadgets based on libsnark and encapsulates some of the main interfaces available to third-party libraries. The libsnark library implements the zkSNARK scheme, an encryption method used to prove/verify the integrity of computations in zero knowledge. See the libsnark library[for instructions].(https://github.com/scipr-lab/libsnark/blob/master/README.md)

## Compile

### Dependency

```bash
sudo apt-get install libgmpxx4ldbl 
sudo apt-get install libgmp-dev 
sudo apt-get install libprocps4-dev
sudo apt-get install libboost-dev
```

### Compile libcsnark

```bash
cd libcsnark
mkdir build
cd build
cmake ../ -DMONTGOMERY_OUTPUT=OFF -DBINARY_OUTPUT=OFF 
```

