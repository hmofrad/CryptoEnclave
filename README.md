# CryptoEnclave for Linux SGX
Cryptographic Enclave for Intel SGX

Install linux-sgx-driver (https://github.com/01org/linux-sgx-driver)

Install linux-sgx (https://github.com/hmofrad/linux-sgx)

Copy CryptoEnclave folder under linux-sgx/SampleCode/
~~~~
cd linux-sgx/SampleCode/
git clone https://github.com/hmofrad/CryptoEnclave
~~~~
Install CryptoEnclave
~~~~
make clean && make
~~~~
