01. Introduction

02. DPDK based Openssl Engine Directory Structure

03. Supported Platforms

    - CN96XX, CN98XX, CN10XX

04. Testing DPDK based Openssl Engine

05. Benchmarking DPDK based Openssl Engine

06. Making Engine as static engine

07. Notes

08. Known Issues


01. Introduction
================
  This README gives overview of contents of this release, supported platform, known issues
  and pre-requisite to build and run DPDK based Openssl engine.

  For sake of simplicity, DPDK based Openssl engine in this release will be referred as
  'Openssl engine' in rest of the document.

02. DPDK based Openssl Engine Directory Structure
=================================================
  Openssl engine directory structure looks like:

  openssl-engine-dpdk
      | \|
      | \|---.c
      | \|      (engine sources)
      | \|---patches/
      | \|      (contain patches to be applied on dependent sources)
      | \|---scripts/
      | \|      (contain board setup scripts)
      | \|---doc/
      | \|      (contain README.txt and openssl.cnf)

03. Supported Platforms
=======================
  This release supports CN96XX, CN98XX, CN10XX
  The cryptodev PMDs supported on each platform are:
  1. CN96XX, CN98XX - librte_crypto_octeontx2, librte_crypto_openssl
  2. CN10XX - librte_crypto_cn10k

I) Dependencies
---------------
  Following sources are pre-requisite for Openssl Engine solution and should be
  built beforehand:

  | a) SDK : Base SDK, engine release supported with. See Release Notes.
  | b) DPDK : Provided in SDK package (Supported versions: 20.11, 21.11, 22.11, 23.11)
  | c) OpenSSL : openssl-1.1.1q
  | d) Require ninja, meson utilities.

  The SDK is not used on the Intel X86 platform and is optional

II) Building and Running Instructions
-------------------------------------
  Openssl engine is released in two modes:
   * Generic Solution in SDK package
   * Standalone

  i) Building openssl engine in 'Generic Solution' release mode for CN96XX, CN98XX, CN10XX

  If released as 'generic solution' with SDK package, engine sources would be provided in
  SDK release package. Refer to SDK documentation for build instructions of engine solution.
  SDK build procedure will build dependencies too. Final libs and bins are available in build
  directory.

  If released as 'standalone', user would need to install and setup dependencies
  manually, refer to following section for manual building

  ii) Building dependencies manually in 'Standalone' mode for CN96XX, CN98XX, CN10XX

    | Note:
    | - <PACKAGE_DIR> - directory where SDK is untarred
    | - <SDK_PATH> in following subsections refers to path to <PACKAGE_DIR>/base_sdk/sources
    | - <TOOLCHAIN_PATH> refers to <SDK_PATH>/toolchain/marvell-tools-XXX.0/bin
    | - <OPENSSL_DIR> refers to compiled openssl-1.1.1q directory generated after following
      openssl-1.1.1q build instructions
    | - <DPDK_DIR> refers to directory where dpdk sources are untarred
    | - <ENGINE_DIR> refers to directory containing Openssl engine sources
    | - <SDK_NAME> is name of SDK , example, SDK10.0-ED1001 while building with SDK10.0-ED1001

    Following subsections covers instructions for building dependent packages.
    a) Building SDK

       Refer to SDK documentation for build instruction of SDK

    b) Building OpenSSL

        Cross compile openssl-1.1.1q.tar.gz package:

        # tar -zxf openssl-1.1.1q.tar.gz

        # cd openssl-1.1.1q

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


    d) Building Engine

	  export OPENSSL_INSTALL=/path/to/openssl/build/directory

      # cd <ENGINE_DIR>

      # cross-compile for CN96XX, CN98XX, CN10XX

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y

    NOTE : Please add DPDK_PC="/absoule/path/till/pkgconfig" to make command if
           prefix is used with meson command while building engine.
      ex:
        dpdk_src $ meson cross_build --cross-file config/arm/arm64_octeontx2_linux_gcc
                   --prefix=/usr/lib && ninja-build -C cross_build

        Running the below command will build dpdk_engine.so

        #make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y
         DPDK_PC=/absolute/path/till/install_dir/usr/lib/pkgconfig

      # to enable openssl.cnf support for dpdk_engine
      # engine compiled with OSSL_CONF=y cannot be run without openssl.cnf file

        make CROSS=<TOOLCHAIN_PATH>/aarch64-marvell-linux-gnu- OTX2=y OSSL_CONF=y


III) Setting up board to run Openssl Engine
-------------------------------------------
  This section covers steps required to set up target to run engine.

  a) Setting up openssl engine in 'Generic Solution' release mode

  If openssl engine solution is provided as 'generic solution' along with SDK
  release package, then all of libs and binaries would be available as part of
  built rootfs images. User should boot board with that rootfs image and find
  following libraries inside /usr directory

     # Openssl engine library dpdk_engine.so at /usr/local/lib/engines-1.1/
     # Openssl libraries libcrypto.so, libssl.so at /usr/lib/
     # Openssl application library openssl at /usr/bin/
     # Scripts to setup CPT VFS and hugepages at /usr/share/openssl-engine-dpdk/
     # DPDK library libdpdk.so at /usr/lib/
     # DPDK PMD libraries under /usr/lib/dpdk/pmds-<ABI_VERSION>/

  User should run platform specific scripts to setup required resources before
  launching engine:
      - for CN10XX,

          source /usr/share/openssl-engine-dpdk/openssl-engine-dpdk-cn10k.sh /bin/dpdk-devbind.py

      - for CN96XX, CN98XX,

          source /usr/share/openssl-engine-dpdk/openssl-engine-dpdk-otx2.sh /bin/dpdk-devbind.py

  Since the binaries and libraries are present at their expected locations in rootfs,
  all the testing and benchmarking commands mentioned in sections (4) and (5)
  of this README can now be run directly from any directory, for example

          openssl speed -elapsed rsa2048

  b) Setting up openssl engine in 'Standalone' release mode

  If openssl engine solution is provided standalone, then user manually need to copy
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

      Use below command to find the <DPDK_PMD_PATH> (in build system)
        $ strings <DPDK_LIB_DIR>/librte_eal.so | grep DPDK_PLUGIN_PATH

      copy required PMD *.so (librte_crypto_cnxk) files
        from <DPDK_LIB_DIR>/dpdk/pmds-<ABI_VERSION>/ to <DPDK_PMD_PATH>

    # copy compiled <ENGINE_DIR> on to target board as <ENGINE_LIB_DIR>

    # mkdir -p /usr/local/lib/engines-1.1/

    # cp <ENGINE_LIB_DIR>/build/lib/dpdk_engine.so /usr/local/lib/engines-1.1/

    # export LD_LIBRARY_PATH=<DPDK_LIB_DIR>:<OPENSSL_LIB_DIR>

    # run the platform specific scripts (requires Python)

      copy <DPDK_DIR>/usertools/dpdk-devbind.py to the target board

      cd <ENGINE_LIB_DIR>/scripts

        - for CN98XX and CN10XX

          sh openssl-engine-dpdk-otx2.sh <path to dpdk-devbind.py>

        - for CN10XX

          sh openssl-engine-dpdk-cn10k.sh <path to dpdk-devbind.py>


IV) Supported Features
-----------------------
  This section lists supported features of Openssl engine on CN96XX, CN98XX, CN10XX platform.

  a) RSA async mode with following modulus lengths(in bits):

    i.   512
    ii.  1024
    iii. 2048
    iv.  3072
    v.   4096

  b) AES128/256-CBC async mode
  c) AES128/256-GCM async mode
  d) openssl speed app -multi option
  e) ECDSA and ECDH offload in async mode with the following NIST recommended Elliptic Curves
     over Prime field (reference, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf):

    i.   NIST P-192
    ii.  NIST P-224
    iii. NIST P-256
    iv.  NIST P-384
    v.   NIST P-521

  f) Support Chacha20-poly1305 cipher on OCTEONTX2 96XX(rev:C0) and 98XX.
  g) OpenSSL pipeline feature - allows submission of batch requests to dpdk layer.

04. Testing DPDK based Openssl
===============================
  a) Run OpenSSL without engine

    # openssl s_server -cert <CertificateFile> -key <KeyFile> -port 4433
    # openssl s_client -connect <ip>:<port> -cipher <cipher_name>
    # openssl speed -elapsed rsa2048

  b) Run OpenSSL with engine Using ENV variables to configure openssl engine.
      OTX2_BUS - Override the bus id of CPT device (use 10 for CN96XX and CN98XX, 20 for CN10XX)
      CRYPTO_DRIVER - Override the crypto driver name to use (use "crypto_cn9k" for CN96XX and CN98XX, "crypto_cn10k" for CN10XX)

    #For CN9K board:
         export OTX2_BUS=10
         export CRYPTO_DRIVER=crypto_cn9k

    #For CN10K board:
         export OTX2_BUS=20
         export CRYPTO_DRIVER=crypto_cn10k

    #Create openssl.cnf file:
         HOME                    = .
         openssl_conf = openssl_init
         [ openssl_init ]
         engines = engine_section
         [ eal_params_section ]
         eal_params_common = "E_DPDKCPT --no-telemetry --socket-mem=500 -d librte_mempool_ring.so"
         eal_params_cptpf_dbdf = "0002:10:00.0"

         [ engine_section ]
         dpdk_engine = dpdkcpt_engine_section

         [ dpdkcpt_engine_section ]
         dynamic_path =  /usr/local/lib/engines-1.1/dpdk_engine.so
         eal_params = $eal_params_section::eal_params_common
         eal_pid_in_fileprefix = yes
         eal_core_by_cpu = yes
         eal_cptvf_by_cpu = $eal_params_section::eal_params_cptpf_dbdf
         cptvf_queues = {{0, 0}}
         engine_alg_support = ALL
         crypto_driver = "crypto_cn9k" //For cn10k, use crypto_cn10k
         engine_log_level = ENG_LOG_INFO
         init=1

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed rsa2048
    # OPENSSL_CONF=openssl.cnf openssl s_server -cert <CertificateFile> -key <KeyFile> -port 4433

  f) Running multi-process applications with openssl.cnf file
     Due to the limitations of DPDK, forking applications need to ensure that openssl.cnf file is loaded after fork().
     With openssl speed with -multi option, use OPENSSL_CONF_MULTI env instead of OPENSSL_CONF for this reason.
     Engine is loaded from openssl.cnf

    # OPENSSL_CONF_MULTI=openssl.cnf openssl speed -multi 4 -elapsed rsa2048

05. Benchmarking DPDK based Openssl Engine
==========================================
  Openssl engine can be benchmarked using openssl speed application.

  (See man openssl speed on its usage). Example commands:

  \*Change to <OPENSSL_LIB_DIR>/apps before running these commands.

  a) Benchmark RSA

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed rsa2048

  b) Benchmark RSA async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -async_jobs +26 -elapsed rsa2048

  c) Benchmark ECDSA on nistp256

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed ecdsap256

  d) Benchmark ECDSA on nistp256 in async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -async_jobs +8 -elapsed ecdsap256

  e) Benchmark ECDH on nistp256

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed ecdhp256

  f) Benchmark ECDH on nistp256 in async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -async_jobs +8 -elapsed ecdhp256

  g) Benchmark AES-128-CBC

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -evp aes-128-cbc

  h) Benchmark AES-128-CBC async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -async_jobs +24 -evp aes-128-cbc

  i) Benchmark AES-128-GCM

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -evp aes-128-gcm

  j) Benchmark AES-128-GCM async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -async_jobs +24 -evp aes-128-gcm

  k) Benchmark CHACHA20-POLY1305 async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -async_jobs +24 -evp
    # 	chacha20-poly1305

  l) Running openssl speed with -multi option

    Example for speed command with -multi option for RSA:

    # OPENSSL_CONF=openssl.cnf openssl speed -multi 18 -async_jobs +26 -elapsed rsa2048

   m) Benchmark AES-CBC-HMAC-SHA1 in async mode

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -async_jobs +24 -evp aes-128-cbc-hmac-sha1

    # OPENSSL_CONF=openssl.cnf openssl speed -elapsed -async_jobs +24 -evp aes-256-cbc-hmac-sha1


06.  Notes
=================

    I. Configuring OpenSSL engine using 'openssl.cnf' file
          OpenSSL engine can be configured using OPENSSL CONF FILE.
        [ref: https://www.openssl.org/docs/man1.1.1/man5/config.html]. Some
        parameters that can be configured via conf file are

         a) 'eal params' for DPDK driver initialisation
         b) DPDK crypto driver to be used for crypto acceleration
         c) Number of VFs to be initialised
         d) Distribution of queues between VFs

       Please refer to sample 'openssl.cnf', part of OpenSSL ENGINE sources,
       for syntatical and semantical information on setting up parameters and
       configuration.

   II. Composite Ciphersuites
          For using composite cipher AES-CBC-HMAC-SHA1 on TLS applications,
        The application must set SSL_OP_NO_ENCRYPT_THEN_MAC option on SSL CTX.
        s_client and s_server provides '-no_etm' command line option to do this. (Only in OpenSSL 3.0.0)

07. Known Issues
================
  a) KeyUpdate is not supported in TLSv1.3 when using the cipher suite TLS_CHACHA20_POLY1305_SHA256
  b) Speed is not supported for AES-CBC-HMAC-SHA1.
  c) Speed application works with a maximum application data size of 32KB

..........................................
