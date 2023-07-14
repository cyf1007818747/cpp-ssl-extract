#define OUTPUT_CERTIFICATE_PATH "certificates/"  // if no such folder, there will be error, such change it to empty string

#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509.h>

using namespace std;

struct SSLPacketHeader {
    uint8_t type;
    uint16_t version;
    uint16_t length;
};

void generate_certificate(X509* cert) {
  // cout << "reach cert printing" << endl;
  X509_NAME* subjectName = X509_get_subject_name(cert);
  int commonNameIndex = X509_NAME_get_index_by_NID(subjectName, NID_commonName, -1);
  if (commonNameIndex != -1) {
    // Get the Common Name (CN) field value as an ASN1_STRING
    ASN1_STRING* commonNameASN1 = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subjectName, commonNameIndex));

    // Convert the ASN1_STRING to a C string
    string commonName = reinterpret_cast<const char*> (ASN1_STRING_get0_data(commonNameASN1));
    string fn = OUTPUT_CERTIFICATE_PATH + commonName + ".pem";
    const char* filename = fn.c_str();
    try {
      FILE* file = fopen(filename, "w");
      PEM_write_X509(file, cert);
      fclose(file);
      cout << "Successfully generated pem certificate file. File name: " << filename << endl;
    } catch (const exception& ex) {
      cerr << "Error writing pem file. Make sure the folder 'certificates' exists. Error: " << ex.what() << endl;
    }
  } else {
    char* subjectNameString = X509_NAME_oneline(subjectName, nullptr, 0);
    cout << "Common Name not found in the subject name. subject name: " << subjectNameString << endl;
  }
  // X509_print_fp(stdout, cert); // Print certificate details to stdout
}

void output_ssl_certificate(BIO* bio) {
  // cout << "bio_len: " << BIO_ctrl_pending(bio) << endl;
  while (BIO_ctrl_pending(bio) > 0) {
    // get the length of the certificate from bio
    u_char* len_buf = new u_char[3];
    int bytes_read_len = BIO_read(bio, len_buf, 3);
    int cert_len = len_buf[0]*256*256 + len_buf[1]*256 + len_buf[2];
    // get certificate payload from bio
    unsigned char* cert_buf = new unsigned char[cert_len];
    int bytes_read_payload = BIO_read(bio, len_buf, cert_len);
    // create a new certificate using X509 library
    const unsigned char* const_buf = cert_buf;
    X509* cert = d2i_X509(NULL, &const_buf, cert_len);
    // generate the certificate file
    if (cert != nullptr) {
      generate_certificate(cert);
    }
    delete[] len_buf;
    delete[] cert_buf;
  }
  BIO_reset(bio);
}