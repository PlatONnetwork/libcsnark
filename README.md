# libcsnark 编译说明手册

- [libcsnark 编译说明手册](#libcsnark-编译说明手册)
    - [简述](#简述)
    - [编译](#编译)
        - [安装依赖](#安装依赖)
        - [编译libcsnark库](#编译libcsnark库)

## 简述

libcsnark 是在 libsnark 的基础上进行增加一些 gadgets ,并封装一些主要接口提供给第三方库使用。
而 libsnark 库实现了zkSNARK方案，这是一种加密方法，用于在零知识中证明/验证计算的完整性。
libsnark 库相关的说明请看[这里](https://github.com/scipr-lab/libsnark/blob/master/README.md)

## 编译

### 安装依赖

```bash
sudo apt-get install libgmpxx4ldbl 
sudo apt-get install libgmp-dev 
sudo apt-get install libprocps4-dev
sudo apt-get install libboost-dev
```

### 编译libcsnark库

```bash
cd libcsnark
mkdir build
cd build
cmake ../ -DMONTGOMERY_OUTPUT=OFF -DBINARY_OUTPUT=OFF 
```

