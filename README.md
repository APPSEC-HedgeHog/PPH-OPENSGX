# PPH-OPENSGX

#Contains SGX Implementation and PPH

##Download and boot ubuntu 14.04

###Commands to build and install PPH:

	$ sudo apt-get update
  
	$ sudo apt-get install git
	
	$ git clone https://github.com/APPSEC-HedgeHog/PPHTestCode.git
	
	$ sudo apt-get install openssl
	
	$ sudo apt-get install libtool
	
	$ sudo apt-get install check
	
	$ sudo apt-get install libssl-dev libelf-dev
  
    $ sudo apt-get build-dep qemu
	
	build Open SGX
	$ cd pph-opensgx

	$ cd qemu

	$ ./configure-arch

	$ make -j $(nproc)

	$ cd ../

	$ make -C libsgx

	$ make -C user

	build pph
	$ cd PolyPasswordHasher-C

	$ autoreconf --install
	
	$ ./configure
	
	$ make
	
	$ sudo make install //this will install library and copy the headers to /usr/local**

