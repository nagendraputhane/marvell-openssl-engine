.. SPDX-License-Identifier: Marvell-MIT
	Copyright (c) 2025 Marvell.

Liquid Crypto Provider
=======================
This is only for functionality release

1. Introduction
---------------

The ``Liquid Crypto (LC) Provider`` is an OpenSSL provider designed to offload \
cryptographic operations to Marvell OCTEON SoCs. It utilizes the LC library to \
interface with the hardware, enabling support for various cryptographic algorithms. \
This allows OpenSSL applications to seamlessly take advantage of hardware-accelerated \
cryptography, resulting in improved performance, enhanced scalability for intensive \
workloads, and easy integration with existing OpenSSL-based solutions.

2. OpenSSL LC Provider Directory Structure
--------------------------------------------

OpenSSL provider directory structure looks like:

.. code-block:: none

	 openssl-engine-dpdk/
		  ├── openssl_provider/      # Provider sources
		  ├── pal/
		  │   ├── common/            # Common PAL layer declarations
		  │   └── liquid_crypto/     # Liquid Crypto specific sources
		  ├── patches/               # Patches for dependent sources
		  ├── scripts/               # Scripts for setup
		  └── doc/openssl_provider/  # README and documentation

3. Supported Platforms
----------------------

This release supports CN93XX, CN96XX and CN98XX platforms.

**Dependencies:**
~~~~~~~~~~~~~~~~~~
Following sources are pre-requisites for OpenSSL Provider solution and should be built beforehand:

- Marvell OCTEON PCIe End Point driver
- DPDK (version >=24.11)
- gRPC
- libedit
- DAO (latest version)
- OpenSSL (version 3.3.3)
- Require ninja, meson utilities

4. Building and Installation For Host
--------------------------------------

Following subsections cover instructions for building dependent packages.

**a). Building OpenSSL**

.. code-block:: shell

	 sudo git clone https://github.com/openssl/openssl.git
	 cd openssl
	 git checkout openssl-3.3.3
	 ./Configure
	 sudo make
	 sudo make install

**b). Building DPDK, gRPC, libedit, and DAO**

	For building DPDK, gRPC, libedit, and DAO, please refer to the following guides \
	https://marvellembeddedprocessors.github.io/dao/guides/platform/liquid_crypto.html

	- DPDK : 1.2.1.2.2 section of guide
	- gRPC : 1.2.1.2.4 section of guide
	- libedit : 1.2.1.2.5 section of guide
	- DAO : 1.2.2 section of guide

**c). Building LC provider**

.. code-block:: shell

	 export OPENSSL_INSTALL=/path/to/openssl/install/dir
	 export DPDK_INSTALL=/path/to/dpdk/install/dir
	 export DAO_LC_INSTALL=/path/to/dao/install/dir
	 cd openssl-engine-dpdk
         # For Linux:
	 make BUILD_TYPE=native PAL=lc BUILD_PROVIDER=y
         # For FreeBSD:
         # Only native builds and provider are supported.
         # By default, this builds the LC provider, To build the DPDK provider, set PAL=dpdk.
         gmake -f Makefile.FreeBSD

**d). Installing LC provider**

.. code-block:: shell

         # For Linux:
	 sudo make install PAL=lc
         # For FreeBSD:
         sudo gmake -f Makefile.FreeBSD install PAL=lc

**e). Install OCTEON PCIe End Point driver**

.. code-block:: shell

	# Following steps are needed only if OCTEON PCIe EP driver is not available on the host kernel:
	 sudo modinfo octeon_ep
	 git clone https://github.com/MarvellEmbeddedProcessors/pcie_ep_octeon_host.git
	 cd pcie_ep_octeon_host
	 make
	 cd ./drivers/octeon_ep/
	 sudo make install

5. Building and Installation For OCTEON
----------------------------------------

**a). For LC cards, they are shipped with standard firmware that includes three main components:**

	- Low-level firmware for hardware initialization and management
	- Marvell SDK Linux kernel
	- Buildroot-based root filesystem (rootFS)

.. note::

	 Please follow the below link for more details:
	 https://marvellembeddedprocessors.github.io/dao/guides/platform/liquid_crypto.html#card-firmware

**b). For Non LC cards (CN96XX, CN98xx)**

	Please refer to the following link for more details:
	https://marvellembeddedprocessors.github.io/dao/guides/platform/liquid_crypto.html#building-card-firmware


6. Supported Features
----------------------

This section lists supported features of the OpenSSL provider.

**a) RSA mode with the following modulus lengths (in bits):**

- 512
- 1024
- 2048
- 3072
- 4096
- 7680

**b) AES128/256-CBC mode**

7. Setting up Host to run OpenSSL LC Provider
---------------------------------------------

**a). Ensure the Liquid Crypto card is booted and the agent app is running on the OCTEON.**

**b). Run the setup script to initialize the Liquid Crypto environment:**

.. code-block:: shell

	 cd scripts
	 sudo ./openssl-lc-setup.sh

The script performs the following steps:

- Removes and reinserts the ``octeon_ep`` kernel module.
- Checks ``dmesg`` logs for successful PF driver load.
- Obtains the BDF of the device.
- Enables SR-IOV with 1 VF.
- Allocates hugepages.
- Loads the ``vfio-pci`` module.
- Allows VFIO without IOMMU.
- Binds the device to the ``vfio-pci`` driver.

.. note::

	 Make sure the hardware platform is initialized and all required kernel modules and drivers are loaded. You can verify successful setup by checking for a "Setup complete" message in the setup script output.

**c). Run the Card Manager:**

	The dao_card_mgr application is a user-space tool designed to manage and configure Liquid Crypto cards. \
	Before running OpenSSL applications with hardware acceleration, ensure the Liquid Crypto card is initialized \
	and configured using the card manager.

.. note::

	Please refer to the following link for more details on how to run the card manager:
	https://marvellembeddedprocessors.github.io/dao/guides/platform/liquid_crypto.html#run-the-card-manager

**d). Set environment variables:**

.. code-block:: shell

	 export LD_LIBRARY_PATH=/path/to/openssl/lib:/path/to/dpdk/lib:/path/to/dao/lib:$LD_LIBRARY_PATH

8. Testing OpenSSL LC Provider
------------------------------

**a). Run OpenSSL list command to check provider capabilities.**

.. code-block:: shell

	./openssl list -providers -cipher-algorithms -provider lc_provider
	# Result of the above command is as:
	Provided:
		{ 2.16.840.1.101.3.4.1.2, AES-128-CBC, AES128 } @ lc_provider
		{ 2.16.840.1.101.3.4.1.42, AES-256-CBC, AES256 } @ lc_provider

	Providers:
	  lc_provider
	    name: OPENSSL LC PROVIDER
	    version: 1.0
	    status: active

**b). Default Provider**
	Along with LC provider, the OpenSSL's built-in provider (default provider) has to be loaded. This is required to have fallback to software implementations for unsupported operations (e.g., RNG).
	It is important that the default provider is loaded only AFTER the LC provider. This is done by the following command line arguments to OpenSSL applications:

.. code-block:: shell

	 -provider lc_provider -provider default

**c). Run OpenSSL s_server with provider**

.. code-block:: shell

	 cd <OPENSSL_LIB_DIR>/apps
	 ./openssl s_server -provider lc_provider -provider default -cert <CertificateFile> -key <KeyFile> -port 4433

**d). Run OpenSSL s_client on peer machine to connect to s_server running on the Host with LC provider.**

.. code-block:: shell

	 ./openssl s_client -connect <ip>:<port> -cipher <cipher_name>

.. note::

	- Replace `<CertificateFile>`, `<KeyFile>`, `<ip>`, `<port>`, and `<cipher_name>` with appropriate values.
	- For example,
	-    ./openssl s_server -provider lc_provider -provider default -cert certs/server.crt -key certs/private.key -port 4433
	-    ./openssl s_client -connect <IP>:4433 -cipher ECDHE-RSA-AES128-SHA

9. Benchmarking OpenSSL LC Provider
-----------------------------------

OpenSSL provider can be benchmarked using the ``openssl speed`` application.

(See ``man openssl speed`` for usage). Example commands:

*Change to <OPENSSL_LIB_DIR>/apps before running these commands.*

a). Benchmark RSA

.. code-block:: shell

	 ./openssl speed -provider lc_provider -provider default -elapsed rsa2048

b). Benchmark RSA async mode

.. code-block:: shell

	 ./openssl speed -provider lc_provider -provider default -async_jobs 26 -elapsed rsa2048

c). Benchmark AES-128-CBC

.. code-block:: shell

	 ./openssl speed -provider lc_provider -provider default -elapsed -evp aes-128-cbc

d). Benchmark AES-128-CBC async mode

.. code-block:: shell

	 ./openssl speed -provider lc_provider -provider default -elapsed -async_jobs 24 -evp aes-128-cbc

10. Known Issues
-----------------

- AES operations are limited to a payload size of 5120 bytes. Operations exceeding this size will fail with an error.
- Multi-process mode is not supported in the FreeBSD environment.
- EC Point Multiplication is currently not supported.
- OpenSSL speed test supports upto 8 processes with LC provider.
- ECDSA sign and verify operations are supported only with s_server and s_client and speed app is not yet supported.
