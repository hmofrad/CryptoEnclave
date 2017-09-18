## Install CryptoEnclave app:
~~~~
# First install linux-sgx sdk on your machine.
make clean && make
~~~~

## Run CryptoEnclave app:
~~~~
./app -a <sha256|hmac_sha256|aes_ecb|aes_cbc> [-userkey|-randomkey <key|keylen>] -intext|-infile <input>
~~~~

## Test CryptoEnclave app:	
* TEST #1: SHA 256

	* Input text
	~~~~
	./app -a sha256 -intext "the quick brown fox jumps over the lazy dog"
	# Verify the result at http://hash.online-convert.com/sha256-generator
	~~~~
	
	* Input file (~200mb)
	~~~~
	./app -a sha256 -infile gutenberg/out.txt
	# Verify the result at https://md5file.com/calculator
	~~~~

* TEST#2: HMAC SHA 256

	* Input text + input key
		~~~~
		./app -a hmac_sha256 -userkey "password" -intext "the quick brown fox jumps over the lazy dog"
		# Verify the result at http://hash.online-convert.com/sha256-generator
		~~~~
		
	* Input text + random key	
		~~~~
		./app -a hmac_sha256 -randomkey 8 -intext "the quick brown fox jumps over the lazy dog"
		~~~~

	* Input file + input key (~100mb)
		~~~~
		./app -a hmac_sha256 -userkey "password" -infile gutenberg/out1.txt
		# Verify results at http://hash.online-convert.com/sha256-generator
		~~~~

	* Input file + input key (~200mb)
		~~~~
		./app -a hmac_sha256 -userkey "password" -infile gutenberg/out.txt
		~~~~
		
	* Input text + random key (~200mb)
		~~~~
		./app -a hmac_sha256 -randomkey 8 -infile gutenberg/out.txt
		~~~~

* TEST#3: AES ECB 128|192|256
	
	* Input text + random key (16|24|32)
	~~~~
	./app -a aes_ecb -randomkey 16 -intext "the quick brown fox jumps over the lazy dog"
	$ Verify the result at http://aes.online-domain-tools.com/
	~~~~
	
	* Input file + random key (16|24|32)
	~~~~
	./app -a aes_ecb -randomkey 16 -infile gutenberg/4300-0.txt
	Verify the result at http://aes.online-domain-tools.com/
	~~~~
	
	* Input file + random key (16|24|32) (~200mb)
	~~~~
	./app -a aes_ecb -randomkey 16 -infile gutenberg/out.txt
	~~~~


* TEST#4: AES CBC 128|192|256

	* Input text + random key (16|24|32)
	~~~~
	./app -a aes_cbc -randomkey 16 -intext "the quick brown fox jumps over the lazy dog"
	# Verify the result at http://aes.online-domain-tools.com/
	~~~~
	
	* Input file + random key (16|24|32)
	~~~~
	./app -a aes_ecb -randomkey 16 -infile gutenberg/4300-0.txt
	# Verify the result at http://aes.online-domain-tools.com/
	~~~~

	* Input file + random key (16|24|32) (~200mb)
	~~~~
	./app -a aes_ecb -randomkey 16 -infile gutenberg/out.txt
	~~~~

## Contact

	(c) Mohammad H. Mofrad, 2017
	(e) mohammad.hmofrad@pitt.edu
