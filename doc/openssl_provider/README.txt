01. Introduction

02. DPDK based Openssl Provider Directory Structure

03. Supported Platforms

04. Testing DPDK based Openssl Provider

05. Benchmarking DPDK based Openssl Provider

06. Known Issues


01. Introduction
================
  The concept of providers was introduced in OpenSSL 3.0. More details on
  providers can be found at (https://www.openssl.org/docs/manmaster/man7/provider.html).
  This README gives overview of contents of this release, supported platform, known issues
  and pre-requisite to build and run DPDK based Openssl provider.

  For sake of simplicity, DPDK based Openssl provider in this release will be referred as
  'Openssl provider' in rest of the document.

02. DPDK based Openssl Provider Directory Structure
=================================================
  Openssl provider directory structure looks like:

  openssl-engine-dpdk
      | \|
      | \|---openssl_provider/
      | \|      (provider sources)
      | \|---pal/
      | \|      (crypto sources)
      | \|---patches/
      | \|      (contain patches to be applied on dependent sources)
      | \|---scripts/
      | \|      (contain board setup scripts)
      | \|---doc/openssl_provider
      | \|      (README and other documentation)

03. Supported Platforms
=======================
  This release supports CN96XX, CN98XX and CN106XX platforms.
  The cryptodev PMDs supported on each platform are:
  1. CN96XX, CN98XX, CN106XX - librte_crypto_cnxk, librte_crypto_openssl

I) Dependencies
---------------
  Following sources are pre-requisite for Openssl Provider solution and should be
  built beforehand:

  | a) SDK : Base SDK, provider release supported with. See Release Notes.
  | b) DPDK : Provided in SDK package (Supported versions: 20.11)
  | c) OpenSSL : openssl >= 3.3.2
  | d) Require ninja, meson utilities.

  The SDK is not used on the Intel X86 platform and is optional

II) Building and Running Instructions
-------------------------------------
  Openssl provider is released in two modes:
   * Generic Solution in SDK package (Yet to be released)
   * Standalone

  i) Building openssl provider in 'Generic Solution' release for OCTEON

  If released as 'generic solution' with SDK package, provider sources would be provided in
  SDK release package. Refer to SDK documentation for build instructions of provider solution.
  SDK build procedure will build dependencies too. Final libs and bins are available in build
  directory.

  If released as 'standalone', user would need to install and setup dependencies
  manually, refer to following section for manual building

  ii)  This is strictly for developers and for any users of provider solution,
       the "Generic solution" is preferred mode of usage

    | Note:
    | - <PACKAGE_DIR> - directory where SDK is untarred
    | - <SDK_PATH> in following subsections refers to path to <PACKAGE_DIR>/base_sdk/sources
    | - <TOOLCHAIN_PATH> refers to <SDK_PATH>/toolchain/marvell-tools-XXX.0/bin
    | - <OPENSSL_DIR> refers to compiled openssl-3.3.2 directory generated after following
      openssl-3.3.2 build instructions
    | - <DPDK_DIR> refers to directory where dpdk sources are untarred
    | - <PROVIDER_DIR> refers to directory containing Openssl provider sources
    | - <SDK_NAME> is name of SDK , example, SDK10.0-ED1001 while building with SDK10.0-ED1001

    Following subsections covers instructions for building dependent packages.
    a) Building SDK

       Refer to SDK documentation for build instruction of SDK

    b) Building OpenSSL

        Cross compile openssl-3.3.2.tar.gz package:

        # tar -zxf openssl-3.3.2.tar.gz

        # cd openssl-3.3.2

        # ./Configure linux-aarch64 --cross-compile-prefix= <TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu-

        # make

    c) DPDK

      Setting up DPDK sources

      # cd <SDK_PATH>/base-sources-<SDK_NAME>/dpdk/

      # tar -xjf sources-dpdk-<DPDK_VERSION>-<SDK_NAME>.tar.bz2,

      # cd <DPDK_DIR>

      Building DPDK sources

	  SDK_DIR $ source env_setup

	  dpdk_src $ meson cross_build --cross-file config/arm/arm64_octeontx2_linux_gcc
	  				&& ninja-build -C cross_build

	  dpdk_src $ mkdir install_dir
	  dpdk_src $ export DESTDIR=/absolute/path/till/install_dir
	  dpdk_src $ cd cross_build/
	  cross_build $ ninja install
	  export DPDK_INSTALL=/absolute/path/till/install_dir


    d) Building provider

	  export OPENSSL_INSTALL=/path/to/openssl/build/directory

      # cd <PROVIDER_DIR>

      # cross-compile for CN96XX, CN98XX, CN106XX

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y

    NOTE : Please add DPDK_PC="/absolute/path/till/pkgconfig" to make command if
           prefix is used with meson command while building provider.
      ex:
        dpdk_src $ meson cross_build --cross-file config/arm/arm64_octeontx2_linux_gcc
                   --prefix=/usr/lib && ninja-build -C cross_build

        Running the below command  will build dpdk_provider.so

        #make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- BUILD_OPENSSL_PROVIDER=y OTX2=y
         DPDK_PC=/absolute/path/till/install_dir/usr/lib/pkgconfig

III) Setting up board to run Openssl Provider
-------------------------------------------
  This section covers steps required to set up target to run provider.

  a) Setting up openssl provider in 'Generic Solution' release mode

  If openssl provider solution is provided as 'generic solution' along with SDK
  release package, then all of libs and binaries would be available as part of
  built rootfs images. User should boot board with that rootfs image and find
  following libraries inside /usr directory

     # Openssl provider library dpdk_provider.so at /usr/local/lib/ossl-modules/
     # Openssl libraries libcrypto.so, libssl.so at /usr/lib/
     # Openssl application library openssl at /usr/bin/
     # Scripts to setup CPT VFS and hugepages at /usr/share/openssl-provider-dpdk/
     # DPDK library libdpdk.so at /usr/lib/
     # DPDK PMD libraries under /usr/lib/dpdk/pmds-<ABI_VERSION>/

  User should run platform setup scripts to setup required resources before
  launching provider:

      - for CN9K board,

          sh /usr/share/openssl-provider-dpdk/openssl-provider-dpdk-otx2.sh /bin/dpdk-devbind.py

      - for CN10K board,

          sh /usr/share/openssl-provider-dpdk/openssl-engine-dpdk-cn10k.sh /bin/dpdk-devbind.py

  Since the binaries and libraries are present at their expected locations in rootfs,
  all the testing and benchmarking commands mentioned in sections (4) and (5)
  of this README can now be run directly from any directory, for example

          openssl speed -provider dpdk_provider -provider default -elapsed rsa2048

  b) this is strictly for developers and for any users of provider solution,
     the "Generic solution" is preferred mode of usage

  If openssl provider solution is provided standalone, then user manually need to copy
  libs and binaries on to the board. Following steps describes manual way to copy
  binaries

    # copy compiled DPDK and openssl sources on to target board

      <DPDK_DIR>/build/lib on to the target board as <DPDK_LIB_DIR>

      <OPENSSL_DIR> on to the target board as <OPENSSL_LIB_DIR>

    # copy DPDK PMDs to <DPDK_PMD_PATH>

      find <ABI_VERSION>
        cat <DPDK_DIR>/ABI_VERSION

      default <DPDK_PMD_PATH> might be one of the below based on dpdk meson config
        - /usr/lib/dpdk/pmds-<ABI_VERSION>/
        - /usr/local/lib/dpdk/pmds-<ABI_VERSION>/

      Use one of the below commands to find the <DPDK_PMD_PATH> (in build system)
        $ python3 ./usertools/dpdk-pmdinfo.py -p <DPDK_LIB_DIR>/librte_eal.so
        $ strings <DPDK_LIB_DIR>/librte_eal.so | grep DPDK_PLUGIN_PATH

      copy required PMD *.so (librte_crypto_octeontx2) files
        from <DPDK_LIB_DIR>/dpdk/pmds-<ABI_VERSION>/ to <DPDK_PMD_PATH>

    # copy compiled <PROVIDER_DIR> on to target board as <PROVIDER_LIB_DIR>

    # mkdir -p /usr/local/lib/ossl-modules/

    # cp <PROVIDER_LIB_DIR>/dpdk_provider.so /usr/local/lib/ossl-modules/

    # export LD_LIBRARY_PATH=<DPDK_LIB_DIR>:<OPENSSL_LIB_DIR>

    # run the platform setup scripts (requires Python)

      copy <DPDK_DIR>/usertools/dpdk-devbind.py to the target board

      cd <PROVIDER_LIB_DIR>/scripts

      - for CN9K board,

          sh openssl-provider-dpdk-otx2.sh <path to dpdk-devbind.py>

      - for CN10K board,

          sh openssl-engine-dpdk-cn10k.sh <path to dpdk-devbind.py>


IV) Supported Features
-----------------------
  This section lists supported features of Openssl provider on OCTEON9 and OCTEON10 platform.

  a) RSA async mode with following modulus lengths(in bits): (under development)

    i.   512
    ii.  1024
    iii. 2048
    iv.  3072
    v.   4096
    vi.  7068

  b) AES128/256-CBC async mode
  c) AES128/256-GCM async mode
  d) openssl speed app -multi option
  e) ECDSA and ECDH offload in async mode with the following NIST recommended Elliptic Curves
     over Prime field (reference, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf):
     (under development)

    i.   NIST P-192
    ii.  NIST P-224
    iii. NIST P-256
    iv.  NIST P-384
    v.   NIST P-521

  f) Support Chacha20-poly1305 cipher on OCTEON9 and OCTEON10.

04. Testing DPDK based Openssl Provider
=====================================
  a) Run OpenSSL list command to check provider capabilities

    # cd <OPENSSL_LIB_DIR>/apps

    # ./openssl list -providers -cipher-algorithms -signature-algorithms -asymcipher-algorithms -key-exchange-algorithms -provider dpdk_provider

    Result of the above command is as below:

    Provided:
      { 2.16.840.1.101.3.4.1.46, aes-256-gcm, id-aes256-GCM } @ dpdk_provider
      { 2.16.840.1.101.3.4.1.6, aes-128-gcm, id-aes128-GCM } @ dpdk_provider
      { 2.16.840.1.101.3.4.1.42, AES-256-CBC, AES256 } @ dpdk_provider
      { 2.16.840.1.101.3.4.1.2, AES-128-CBC, AES128 } @ dpdk_provider
    -
    Providers:
      dpdk_provider
        name: OpenSSL DPDK Provider
        version: 1.0
        status: active

    If we run above command on OCTEON9 and OCTEON10, then we will see
    one more supported cipher. [ChaCha20-Poly1305]

  b) Default Provider

    Along with DPDK provider, the OpenSSL's built in provider (default provider) has to be loaded.
    This is required to have fallback to software implementations for unsupported operations (Ex: RNG).

    It is important that the default provider is loaded only AFTER the DPDK provider.
    This is done by the following command line aruguments to openssl applications.

    -provider dpdk_provider -provider default

  c) Run OpenSSL s_server with provider

    # cd <OPENSSL_LIB_DIR>/apps

    # ./openssl s_server -provider dpdk_provider -provider default -cert <CertificateFile> -key <KeyFile> -port 4433

  d) Run OpenSSL s_client on peer machine to connect to s_server running
     on the board

    # ./openssl s_client -connect <ip>:<port> -cipher <cipher_name>

05. Benchmarking DPDK based Openssl Provider
==========================================
  Openssl provider can be benchmarked using openssl speed application.

  (See man openssl speed on its usage). Example commands:

  \*Change to <OPENSSL_LIB_DIR>/apps before running these commands.

  a) Benchmark RSA

    # ./openssl speed -provider dpdk_provider -provider default -elapsed rsa2048

  b) Benchmark RSA async mode

    # ./openssl speed -provider dpdk_provider -provider default -async_jobs +26 -elapsed rsa2048

  c) Benchmark ECDSA on nistp256

    # ./openssl speed -provider dpdk_provider -provider default -elapsed ecdsap256

  d) Benchmark ECDSA on nistp256 in async mode

    # ./openssl speed -provider dpdk_provider -provider default -async_jobs +8 -elapsed ecdsap256

  e) Benchmark ECDH on nistp256

    # ./openssl speed -provider dpdk_provider -provider default -elapsed ecdhp256

  f) Benchmark ECDH on nistp256 in async mode

    # ./openssl speed -provider dpdk_provider -provider default -async_jobs +8 -elapsed ecdhp256

  g) Benchmark AES-128-CBC

    # ./openssl speed -provider dpdk_provider -provider default -elapsed -evp aes-128-cbc

  h) Benchmark AES-128-CBC async mode

    # ./openssl speed -provider dpdk_provider -provider default -elapsed -async_jobs +24 -evp aes-128-cbc

  i) Benchmark AES-128-GCM

    # ./openssl speed -provider dpdk_provider -provider default -elapsed -evp aes-128-gcm

  j) Benchmark AES-128-GCM async mode

    # ./openssl speed -provider dpdk_provider -provider default -elapsed -async_jobs +24 -evp aes-128-gcm

  k) Benchmark CHACHA20-POLY1305 async mode

	# ./openssl speed -provider dpdk_provider -provider default -elapsed -async_jobs +24 -evp
	# 	chacha20-poly1305

  l) Running openssl speed with -multi option

    A patch is provided with the package for use with the speed -multi option.

    This is required to address the limitation in the speed application
    while aggregating the performance across cores.

    The limitation causes speed to report higher than actual performance.

    Build openssl 3.3.2 package after applying speed_multi patch in patches directory:

      # cd openssl-3.3.2

      # patch -p1 < <openssl-provider-directory>/patches/speed_multi.patch

    Example for speed command with -multi option for RSA:

      # ./openssl speed -provider dpdk_provider -provider default -multi 18 -async_jobs +26 -elapsed rsa2048

06. Known Issues
================
  a) Multi Call for AES-GCM and Chacha20-Poly1305 not supported

