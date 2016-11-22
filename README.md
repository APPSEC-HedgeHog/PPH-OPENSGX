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
	
Steps before pushing a commit to Git.

1. cd polypasswordhasher-src and do a make clean
2. cd user and do a make clean
3. cd libsgx and do a make clean
4. rm *.sgx and *.conf files generated in user/pph_enclave folder
5. rm sign.key file in root of repository.
6. remove temporary files that end with a ~(tilde)
7. rm -rf PolyPasswordHasher-C/m4
8. rm -rf PolyPasswordHasher-C/config.log
9. rm user/enclu.c

do a git status in root of repository to find out what changes are done and what are the untracked files
if you find still some changes after this that you havent done, then delete them.

Now git add individual files that you have changed
git add <filename> //dont do git add --all

if you accidentally add in a commit then
do git reset HEAD <file-name>  to remove that file from staging area

git commit //write something meaningful and save

git push origin master

