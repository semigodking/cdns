# cdns
cdns is an experimental tool to cure your poisoned DNS. The benifits are:

1. No VPN required
2. You can use many foreign DNS servers as upstream server.
3. You can get really good experience if you use fast foreign DNS server
as up stream server.

# HOW TO BUILD
### Prerequisites
The following libraries are required.

* libevent2
* argp-standalone (Required for OpenWRT build only)

### Steps
On general linux, run commands below to build with CMake.

	mkdir build
	cd build
	cmake ../
	make

A simple Makefile is also provided for build without CMake.(Note: this
building method is not to be maintained.

	make

To build with OpenWRT toolchain, read documents here (http://wiki.openwrt.org/doc/devel/crosscompile) for how to
cross compile. This is an example:
 
	export PATH=$PATH:/openwrt_cc/staging_dir/host/bin/:/openwrt_cc/staging_dir/toolchain-mips_mips32_gcc-4.8-linaro_uClibc-0.9.33.2/bin/
	export STAGING_DIR=/openwrt_cc/staging_dir/toolchain-mips_mips32_gcc-4.8-linaro_uClibc-0.9.33.2/
	export TARGET_DIR=/openwrt_cc/staging_dir/target-mips_mips32_uClibc-0.9.33.2
	export CFLAGS="-mips32 -mtune=mips32 -I$TARGET_DIR/usr/include/ -L$TARGET_DIR/usr/lib/"
	make CC=mips-openwrt-linux-gcc LD=mips-openwrt-linux-ld STATIC_LIBS=$TARGET_DIR/usr/lib/libargp.a

# HOW TO RUN
Run cdns like this:

	./cdns -c /path/to/config.json

# Configurations
You can create your configuration file based on 'config.json.example'.


#AUTHOR
[Zhuofei Wang](mailto:semigodking.com) semigodking@gmail.com


