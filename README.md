# SSL Certificate Extractor

## Description
This project is designed to extract SSL certificates from a PCAPNG file and save each certificate as a separate PEM file. It utilizes the pcap library for packet capture processing and OpenSSL for handling SSL certificates.

## Prerequisites
To run this project, you need to have the following libraries installed on your system:
- pcap (libpcap)
- OpenSSL (libssl and libcrypto)

## Installation and Run
1. **Install Dependencies**
   
   Ensure you have the pcap and OpenSSL libraries installed on your system. You can usually install these via your system's package manager. For example, on Ubuntu, you can use:

    `sudo apt-get install libpcap-dev libssl-dev`

2. **Compile the Project**

    Navigate to the project directory and compile the source code using the following command:

    `g++ -std=c++20 ssl_extract.cpp -lpcap -lssl -lcrypto -o ssl_extract.bin`

3. **Usage**
Prepare Your PCAPNG File:

    Place your PCAPNG file in the project directory or specify the path in the FILE_PATH macro in the source code.
Run the Binary:
Execute the compiled binary to start extracting certificates:

    `./ssl_extract.bin`

4. **Check the Output**

    The extracted certificates will be saved in the certificates/ directory as specified by the OUTPUT_CERTIFICATE_PATH macro in the source code. Ensure this directory exists or adjust the path as necessary.

5. **Troubleshooting**

    Directory Issues: If you encounter errors related to the output directory, ensure that the certificates/ directory exists or modify the OUTPUT_CERTIFICATE_PATH to an existing directory.
Permission Issues: Run the binary with sufficient permissions to access the PCAPNG file and write to the output directory.
Dependency Issues: Verify that all required libraries are correctly installed and linked during compilation.
