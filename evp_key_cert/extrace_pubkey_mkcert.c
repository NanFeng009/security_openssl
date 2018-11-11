#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>

#define NONCE_LENGTH     32
int add_ext(X509 *cert, int nid, char *value);


static const unsigned char OCSP_KEY[1708] = {
		0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
		0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x49, 0x49, 0x45,
		0x77, 0x41, 0x49, 0x42, 0x41, 0x44, 0x41, 0x4e, 0x42, 0x67, 0x6b, 0x71, 0x68, 0x6b, 0x69, 0x47,
		0x39, 0x77, 0x30, 0x42, 0x41, 0x51, 0x45, 0x46, 0x41, 0x41, 0x53, 0x43, 0x42, 0x4b, 0x6f, 0x77,
		0x67, 0x67, 0x53, 0x6d, 0x41, 0x67, 0x45, 0x41, 0x41, 0x6f, 0x49, 0x42, 0x41, 0x51, 0x44, 0x73,
		0x4e, 0x37, 0x43, 0x6b, 0x37, 0x2f, 0x42, 0x33, 0x6e, 0x4b, 0x78, 0x37, 0x0a, 0x37, 0x76, 0x75,
		0x35, 0x45, 0x6e, 0x77, 0x57, 0x4a, 0x6c, 0x35, 0x63, 0x58, 0x59, 0x65, 0x2f, 0x43, 0x32, 0x43,
		0x77, 0x68, 0x50, 0x6c, 0x54, 0x59, 0x79, 0x50, 0x32, 0x44, 0x6c, 0x61, 0x68, 0x49, 0x4d, 0x63,
		0x65, 0x41, 0x70, 0x54, 0x78, 0x61, 0x73, 0x2f, 0x67, 0x77, 0x39, 0x7a, 0x6c, 0x62, 0x56, 0x72,
		0x69, 0x66, 0x62, 0x50, 0x50, 0x6f, 0x71, 0x70, 0x5a, 0x67, 0x75, 0x75, 0x48, 0x0a, 0x51, 0x54,
		0x77, 0x44, 0x5a, 0x4e, 0x61, 0x41, 0x66, 0x6a, 0x55, 0x53, 0x47, 0x65, 0x59, 0x4f, 0x71, 0x36,
		0x69, 0x32, 0x38, 0x51, 0x41, 0x49, 0x64, 0x6f, 0x35, 0x2f, 0x44, 0x55, 0x43, 0x45, 0x2f, 0x44,
		0x4a, 0x6e, 0x58, 0x48, 0x6d, 0x62, 0x66, 0x74, 0x67, 0x49, 0x55, 0x7a, 0x61, 0x38, 0x6e, 0x54,
		0x72, 0x43, 0x51, 0x57, 0x73, 0x77, 0x47, 0x68, 0x33, 0x57, 0x7a, 0x68, 0x47, 0x74, 0x0a, 0x44,
		0x36, 0x36, 0x56, 0x48, 0x59, 0x77, 0x79, 0x46, 0x6c, 0x68, 0x33, 0x55, 0x34, 0x39, 0x56, 0x38,
		0x78, 0x74, 0x72, 0x71, 0x6e, 0x62, 0x36, 0x43, 0x32, 0x42, 0x58, 0x52, 0x66, 0x77, 0x73, 0x74,
		0x76, 0x6c, 0x4f, 0x49, 0x6e, 0x68, 0x71, 0x79, 0x5a, 0x63, 0x32, 0x42, 0x4e, 0x4e, 0x79, 0x64,
		0x33, 0x54, 0x4c, 0x33, 0x7a, 0x76, 0x31, 0x46, 0x61, 0x59, 0x6f, 0x59, 0x65, 0x77, 0x5a, 0x0a,
		0x42, 0x57, 0x44, 0x2f, 0x41, 0x78, 0x6a, 0x59, 0x6b, 0x42, 0x46, 0x62, 0x75, 0x6a, 0x37, 0x4f,
		0x4c, 0x31, 0x2f, 0x75, 0x79, 0x35, 0x6e, 0x30, 0x6e, 0x6e, 0x70, 0x74, 0x2f, 0x31, 0x73, 0x68,
		0x50, 0x36, 0x78, 0x65, 0x79, 0x45, 0x69, 0x6e, 0x58, 0x56, 0x49, 0x64, 0x38, 0x33, 0x6a, 0x54,
		0x51, 0x38, 0x6a, 0x6d, 0x67, 0x51, 0x47, 0x79, 0x47, 0x57, 0x5a, 0x72, 0x71, 0x57, 0x36, 0x71,
		0x0a, 0x68, 0x53, 0x67, 0x6f, 0x2b, 0x50, 0x45, 0x32, 0x76, 0x53, 0x74, 0x6b, 0x62, 0x43, 0x34,
		0x6a, 0x62, 0x54, 0x31, 0x45, 0x39, 0x59, 0x4c, 0x54, 0x61, 0x36, 0x58, 0x4d, 0x50, 0x46, 0x72,
		0x4d, 0x4d, 0x33, 0x6b, 0x51, 0x45, 0x39, 0x50, 0x77, 0x35, 0x63, 0x54, 0x45, 0x54, 0x64, 0x48,
		0x37, 0x59, 0x36, 0x6d, 0x67, 0x77, 0x54, 0x44, 0x2f, 0x6b, 0x48, 0x72, 0x31, 0x35, 0x76, 0x4c,
		0x74, 0x0a, 0x30, 0x5a, 0x47, 0x35, 0x52, 0x72, 0x34, 0x56, 0x41, 0x67, 0x4d, 0x42, 0x41, 0x41,
		0x45, 0x43, 0x67, 0x67, 0x45, 0x42, 0x41, 0x4a, 0x64, 0x4b, 0x78, 0x2b, 0x6d, 0x72, 0x2f, 0x2f,
		0x45, 0x73, 0x4f, 0x4e, 0x45, 0x62, 0x37, 0x4c, 0x2f, 0x4a, 0x6c, 0x67, 0x34, 0x39, 0x76, 0x74,
		0x77, 0x62, 0x7a, 0x35, 0x44, 0x4f, 0x41, 0x62, 0x79, 0x74, 0x50, 0x6c, 0x39, 0x70, 0x4e, 0x53,
		0x51, 0x6f, 0x0a, 0x5a, 0x4e, 0x58, 0x49, 0x66, 0x35, 0x2b, 0x35, 0x2b, 0x5a, 0x6c, 0x79, 0x56,
		0x76, 0x68, 0x58, 0x6d, 0x6b, 0x69, 0x62, 0x74, 0x4d, 0x55, 0x78, 0x79, 0x35, 0x50, 0x6d, 0x56,
		0x49, 0x4d, 0x47, 0x4e, 0x6b, 0x49, 0x6e, 0x78, 0x76, 0x39, 0x4a, 0x65, 0x35, 0x56, 0x4b, 0x77,
		0x45, 0x54, 0x36, 0x72, 0x33, 0x32, 0x66, 0x39, 0x6d, 0x78, 0x4e, 0x69, 0x54, 0x37, 0x69, 0x61,
		0x44, 0x76, 0x35, 0x0a, 0x79, 0x65, 0x51, 0x69, 0x2f, 0x30, 0x6c, 0x79, 0x55, 0x6a, 0x55, 0x45,
		0x6c, 0x65, 0x73, 0x6e, 0x47, 0x50, 0x7a, 0x50, 0x47, 0x30, 0x35, 0x46, 0x78, 0x68, 0x68, 0x46,
		0x38, 0x65, 0x79, 0x64, 0x69, 0x58, 0x61, 0x31, 0x66, 0x35, 0x54, 0x6b, 0x47, 0x75, 0x49, 0x4e,
		0x71, 0x39, 0x57, 0x70, 0x67, 0x44, 0x6d, 0x46, 0x66, 0x6e, 0x2b, 0x44, 0x36, 0x37, 0x59, 0x55,
		0x79, 0x54, 0x79, 0x37, 0x0a, 0x54, 0x42, 0x77, 0x58, 0x58, 0x36, 0x50, 0x37, 0x68, 0x44, 0x7a,
		0x45, 0x4b, 0x7a, 0x79, 0x46, 0x55, 0x30, 0x68, 0x34, 0x6c, 0x35, 0x58, 0x39, 0x77, 0x34, 0x4b,
		0x59, 0x4c, 0x30, 0x53, 0x76, 0x4a, 0x35, 0x55, 0x6b, 0x4d, 0x34, 0x62, 0x6f, 0x73, 0x65, 0x52,
		0x6b, 0x4a, 0x45, 0x63, 0x79, 0x63, 0x69, 0x68, 0x4d, 0x66, 0x77, 0x76, 0x6c, 0x59, 0x2f, 0x51,
		0x4e, 0x42, 0x33, 0x49, 0x74, 0x0a, 0x64, 0x64, 0x53, 0x43, 0x52, 0x31, 0x43, 0x51, 0x31, 0x38,
		0x4b, 0x41, 0x6d, 0x61, 0x64, 0x73, 0x67, 0x39, 0x66, 0x76, 0x5a, 0x30, 0x59, 0x64, 0x75, 0x5a,
		0x54, 0x6d, 0x33, 0x32, 0x33, 0x4f, 0x62, 0x70, 0x59, 0x4a, 0x6f, 0x31, 0x6a, 0x58, 0x6b, 0x50,
		0x6e, 0x74, 0x58, 0x58, 0x48, 0x48, 0x36, 0x4a, 0x4a, 0x65, 0x6a, 0x75, 0x30, 0x62, 0x33, 0x39,
		0x36, 0x36, 0x4e, 0x58, 0x69, 0x7a, 0x0a, 0x38, 0x58, 0x42, 0x4b, 0x65, 0x6b, 0x45, 0x36, 0x6d,
		0x6b, 0x5a, 0x35, 0x55, 0x6b, 0x6b, 0x4b, 0x38, 0x35, 0x6a, 0x50, 0x6e, 0x6e, 0x5a, 0x6e, 0x42,
		0x4c, 0x53, 0x73, 0x52, 0x6c, 0x65, 0x36, 0x73, 0x36, 0x64, 0x50, 0x48, 0x52, 0x6b, 0x69, 0x67,
		0x73, 0x45, 0x43, 0x67, 0x59, 0x45, 0x41, 0x2f, 0x38, 0x4d, 0x5a, 0x37, 0x73, 0x74, 0x2b, 0x2f,
		0x32, 0x34, 0x33, 0x4d, 0x78, 0x30, 0x54, 0x0a, 0x45, 0x66, 0x4e, 0x36, 0x4d, 0x6b, 0x34, 0x2f,
		0x53, 0x43, 0x53, 0x49, 0x77, 0x59, 0x6f, 0x64, 0x34, 0x77, 0x77, 0x57, 0x48, 0x42, 0x47, 0x42,
		0x31, 0x51, 0x68, 0x41, 0x72, 0x35, 0x76, 0x65, 0x64, 0x47, 0x72, 0x79, 0x39, 0x45, 0x6a, 0x6c,
		0x77, 0x54, 0x57, 0x44, 0x59, 0x2b, 0x57, 0x4f, 0x77, 0x59, 0x75, 0x2f, 0x6b, 0x48, 0x6f, 0x62,
		0x46, 0x41, 0x2b, 0x59, 0x71, 0x37, 0x41, 0x76, 0x0a, 0x36, 0x43, 0x72, 0x6d, 0x45, 0x4d, 0x31,
		0x76, 0x49, 0x75, 0x6c, 0x52, 0x68, 0x68, 0x63, 0x75, 0x61, 0x75, 0x78, 0x52, 0x52, 0x73, 0x78,
		0x6b, 0x57, 0x4b, 0x48, 0x75, 0x55, 0x74, 0x30, 0x77, 0x71, 0x5a, 0x36, 0x71, 0x79, 0x62, 0x30,
		0x34, 0x73, 0x6e, 0x4f, 0x35, 0x54, 0x64, 0x61, 0x74, 0x33, 0x66, 0x4b, 0x62, 0x2f, 0x4a, 0x32,
		0x77, 0x52, 0x4f, 0x46, 0x6f, 0x61, 0x69, 0x47, 0x4d, 0x0a, 0x62, 0x64, 0x36, 0x55, 0x65, 0x61,
		0x35, 0x53, 0x62, 0x75, 0x36, 0x64, 0x30, 0x6e, 0x4f, 0x71, 0x57, 0x50, 0x4f, 0x6b, 0x6a, 0x41,
		0x56, 0x4e, 0x79, 0x67, 0x55, 0x43, 0x67, 0x59, 0x45, 0x41, 0x37, 0x47, 0x2f, 0x76, 0x58, 0x58,
		0x37, 0x55, 0x2b, 0x44, 0x7a, 0x65, 0x70, 0x72, 0x65, 0x66, 0x44, 0x4e, 0x2b, 0x4b, 0x6a, 0x74,
		0x62, 0x42, 0x39, 0x4f, 0x58, 0x6e, 0x68, 0x46, 0x65, 0x67, 0x0a, 0x52, 0x33, 0x50, 0x4d, 0x71,
		0x70, 0x49, 0x68, 0x58, 0x68, 0x53, 0x39, 0x4f, 0x77, 0x61, 0x53, 0x44, 0x5a, 0x65, 0x32, 0x65,
		0x5a, 0x79, 0x76, 0x6c, 0x67, 0x44, 0x2f, 0x67, 0x78, 0x4c, 0x42, 0x73, 0x2b, 0x42, 0x62, 0x64,
		0x6b, 0x46, 0x4c, 0x42, 0x49, 0x7a, 0x4a, 0x75, 0x73, 0x47, 0x53, 0x30, 0x38, 0x39, 0x41, 0x50,
		0x34, 0x55, 0x6e, 0x61, 0x63, 0x33, 0x65, 0x33, 0x47, 0x52, 0x67, 0x0a, 0x41, 0x61, 0x58, 0x77,
		0x6f, 0x31, 0x43, 0x66, 0x41, 0x48, 0x58, 0x56, 0x2b, 0x71, 0x35, 0x58, 0x70, 0x6b, 0x72, 0x63,
		0x75, 0x73, 0x45, 0x39, 0x4b, 0x4a, 0x37, 0x71, 0x77, 0x31, 0x53, 0x50, 0x37, 0x71, 0x6a, 0x57,
		0x67, 0x4a, 0x30, 0x34, 0x33, 0x52, 0x6e, 0x6c, 0x6c, 0x44, 0x35, 0x53, 0x37, 0x4b, 0x6c, 0x62,
		0x50, 0x77, 0x4c, 0x56, 0x37, 0x70, 0x56, 0x76, 0x43, 0x45, 0x6b, 0x4d, 0x0a, 0x49, 0x42, 0x58,
		0x50, 0x72, 0x73, 0x59, 0x36, 0x6b, 0x4e, 0x45, 0x43, 0x67, 0x59, 0x45, 0x41, 0x71, 0x37, 0x4e,
		0x79, 0x44, 0x48, 0x4d, 0x48, 0x44, 0x6a, 0x6f, 0x53, 0x79, 0x72, 0x6a, 0x42, 0x48, 0x62, 0x4d,
		0x45, 0x48, 0x52, 0x4f, 0x55, 0x76, 0x6a, 0x7a, 0x77, 0x70, 0x6d, 0x57, 0x76, 0x7a, 0x4d, 0x5a,
		0x48, 0x62, 0x59, 0x35, 0x2f, 0x52, 0x2b, 0x49, 0x6a, 0x63, 0x77, 0x46, 0x45, 0x0a, 0x4a, 0x59,
		0x6e, 0x4c, 0x45, 0x78, 0x36, 0x42, 0x52, 0x2b, 0x56, 0x43, 0x45, 0x4f, 0x57, 0x43, 0x6f, 0x67,
		0x4c, 0x4d, 0x6c, 0x78, 0x53, 0x79, 0x61, 0x78, 0x52, 0x52, 0x58, 0x53, 0x6d, 0x4a, 0x37, 0x2b,
		0x59, 0x6b, 0x7a, 0x37, 0x44, 0x71, 0x35, 0x46, 0x67, 0x59, 0x68, 0x39, 0x6d, 0x32, 0x4b, 0x73,
		0x66, 0x39, 0x68, 0x48, 0x63, 0x68, 0x41, 0x72, 0x4f, 0x72, 0x53, 0x47, 0x77, 0x41, 0x0a, 0x43,
		0x45, 0x39, 0x68, 0x76, 0x73, 0x2f, 0x4f, 0x61, 0x56, 0x62, 0x78, 0x56, 0x77, 0x56, 0x42, 0x63,
		0x68, 0x67, 0x32, 0x69, 0x69, 0x2f, 0x65, 0x72, 0x30, 0x39, 0x59, 0x42, 0x72, 0x41, 0x42, 0x45,
		0x35, 0x31, 0x79, 0x74, 0x67, 0x48, 0x47, 0x69, 0x33, 0x79, 0x62, 0x37, 0x54, 0x59, 0x44, 0x62,
		0x58, 0x59, 0x62, 0x79, 0x48, 0x69, 0x6a, 0x45, 0x58, 0x55, 0x43, 0x67, 0x59, 0x45, 0x41, 0x0a,
		0x7a, 0x44, 0x70, 0x50, 0x31, 0x30, 0x47, 0x7a, 0x38, 0x67, 0x79, 0x61, 0x41, 0x67, 0x58, 0x2f,
		0x38, 0x35, 0x32, 0x76, 0x30, 0x48, 0x76, 0x2b, 0x6f, 0x32, 0x78, 0x6e, 0x45, 0x37, 0x43, 0x67,
		0x2b, 0x4c, 0x63, 0x30, 0x35, 0x57, 0x30, 0x2b, 0x4e, 0x30, 0x62, 0x51, 0x77, 0x59, 0x69, 0x47,
		0x5a, 0x67, 0x6c, 0x54, 0x44, 0x43, 0x37, 0x6b, 0x6d, 0x44, 0x79, 0x61, 0x65, 0x48, 0x79, 0x65,
		0x0a, 0x4a, 0x71, 0x4b, 0x34, 0x50, 0x69, 0x68, 0x65, 0x42, 0x54, 0x73, 0x62, 0x45, 0x52, 0x38,
		0x64, 0x6c, 0x61, 0x6d, 0x69, 0x68, 0x48, 0x75, 0x65, 0x74, 0x4d, 0x79, 0x6f, 0x49, 0x56, 0x54,
		0x75, 0x66, 0x4e, 0x33, 0x36, 0x51, 0x77, 0x64, 0x6a, 0x6f, 0x49, 0x45, 0x6f, 0x61, 0x4e, 0x56,
		0x70, 0x54, 0x6e, 0x48, 0x42, 0x77, 0x65, 0x73, 0x69, 0x79, 0x64, 0x43, 0x6a, 0x56, 0x6a, 0x2f,
		0x58, 0x0a, 0x35, 0x37, 0x32, 0x64, 0x4d, 0x78, 0x45, 0x62, 0x53, 0x68, 0x69, 0x52, 0x62, 0x77,
		0x42, 0x36, 0x6e, 0x6f, 0x51, 0x58, 0x46, 0x68, 0x46, 0x37, 0x2b, 0x77, 0x37, 0x48, 0x44, 0x72,
		0x41, 0x53, 0x4d, 0x6a, 0x44, 0x45, 0x36, 0x4f, 0x47, 0x2f, 0x4f, 0x74, 0x45, 0x43, 0x67, 0x59,
		0x45, 0x41, 0x37, 0x69, 0x6a, 0x2b, 0x77, 0x6f, 0x58, 0x66, 0x49, 0x62, 0x50, 0x53, 0x2b, 0x2b,
		0x67, 0x45, 0x0a, 0x37, 0x34, 0x38, 0x43, 0x67, 0x58, 0x78, 0x5a, 0x47, 0x66, 0x57, 0x50, 0x48,
		0x79, 0x56, 0x70, 0x5a, 0x39, 0x49, 0x43, 0x56, 0x33, 0x51, 0x51, 0x2f, 0x49, 0x46, 0x69, 0x75,
		0x53, 0x50, 0x6c, 0x47, 0x56, 0x6f, 0x6f, 0x6b, 0x72, 0x42, 0x6d, 0x49, 0x68, 0x66, 0x51, 0x2f,
		0x42, 0x70, 0x76, 0x69, 0x4e, 0x47, 0x72, 0x31, 0x57, 0x63, 0x4b, 0x67, 0x41, 0x79, 0x62, 0x71,
		0x54, 0x50, 0x42, 0x0a, 0x51, 0x47, 0x48, 0x2f, 0x6c, 0x7a, 0x4e, 0x54, 0x74, 0x38, 0x6e, 0x4a,
		0x38, 0x51, 0x76, 0x6e, 0x39, 0x4b, 0x56, 0x44, 0x7a, 0x53, 0x36, 0x55, 0x54, 0x49, 0x50, 0x46,
		0x72, 0x61, 0x42, 0x4e, 0x56, 0x48, 0x6b, 0x76, 0x51, 0x6a, 0x79, 0x6b, 0x4d, 0x68, 0x37, 0x65,
		0x76, 0x72, 0x70, 0x2f, 0x54, 0x73, 0x43, 0x53, 0x75, 0x47, 0x66, 0x52, 0x2f, 0x73, 0x75, 0x31,
		0x32, 0x75, 0x46, 0x75, 0x0a, 0x46, 0x32, 0x71, 0x31, 0x66, 0x75, 0x38, 0x4b, 0x6c, 0x70, 0x58,
		0x56, 0x50, 0x62, 0x6a, 0x55, 0x62, 0x51, 0x47, 0x67, 0x77, 0x67, 0x4d, 0x46, 0x2b, 0x38, 0x49,
		0x3d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41,
		0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a
};

void *load_key(const uint8_t *pem_key, uint32_t len)
{
		EVP_PKEY *pkey = NULL;
		BIO *key = NULL;
		do
		{
				key = BIO_new_mem_buf((void *)pem_key, len);
				if(key == NULL)
				{
						printf("BIO_new_mem_buf error\n");
				}

				pkey = PEM_read_bio_PrivateKey(key, NULL, (pem_password_cb *)NULL, NULL);
				if(pkey == NULL)
				{
						printf("PEM_read_bio_PrivateKey error\n");
				}
		} while (0);

		if (key != NULL)
		{
				BIO_free(key);
		}
		return pkey;
}
int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int serial, int days)
{
		X509 *x;
		EVP_PKEY *pk;
		RSA *rsa;
		X509_NAME *name=NULL;

		if ((pkeyp == NULL) || (*pkeyp == NULL))
		{
				printf("pkeyp is null\n");
				goto err;
		}
		else
		{
				printf("The key is correct\n");
				pk= *pkeyp;
		}

		if ((x509p == NULL) || (*x509p == NULL))
		{
				if ((x=X509_new()) == NULL)
						goto err;
		}
		else
				x= *x509p;

		X509_set_version(x,2);
		ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
		X509_gmtime_adj(X509_get_notBefore(x),0);
		X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
		X509_set_pubkey(x,pk);

		name=X509_get_subject_name(x);
		/* This function creates and adds the entry, working out the
		 *          *       * correct string type and performing checks on its length.
		 *                   *               * Normally we'd check the return value for errors...
		 *                            *                       */
		X509_NAME_add_entry_by_txt(name,"C",
						MBSTRING_ASC, "US", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"ST",
						MBSTRING_ASC, "CA", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"O",
						MBSTRING_ASC, "Intel Corporation", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"OU",
						MBSTRING_ASC, "EPID and SIGMA root signing", -1, -1, 0);
		X509_NAME_add_entry_by_txt(name,"CN",
						MBSTRING_ASC, "www.intel.com", -1, -1, 0);

		/* Its self signed so set the issuer name to be the same as the
		 *          *       * subject.
		 *                   *               */
		X509_set_issuer_name(x,name);

		/* Add various extensions: standard extensions */
		add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
		add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

		add_ext(x, NID_subject_key_identifier, "hash");



		if (!X509_sign(x,pk,EVP_sha1()))
				goto err;

		*x509p=x;
		*pkeyp=pk;
		return(1);
err:
		return(0);
}

/* Add extension using V3 code: we can set the config file as NULL
 *  *  * because we wont reference any other sections.
 *   *   */

int add_ext(X509 *cert, int nid, char *value)
{
		X509_EXTENSION *ex;
		X509V3_CTX ctx;
		/* This sets the 'context' of the extensions. */
		/* No configuration database */
		X509V3_set_ctx_nodb(&ctx);
		/* Issuer and subject certs: both the target since it is self signed,
		 *          *       * no request and no CRL
		 *                   *               */
		X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
		ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
		if (!ex)
				return 0;

		X509_add_ext(cert,ex,-1);
		X509_EXTENSION_free(ex);
		return 1;
}


void dump_to_disk( X509* x509)
{

		char * file_name = "OSCP_KEY.pem";

		FILE * f  = fopen(file_name, "wb");
		if(f == NULL)
				printf("open file failed\n");
		PEM_write_X509(f, x509);
		fclose(f);
		return;
}

int main()
{
		EVP_PKEY *pkey = NULL;
		BIO *bio_err;
		X509 *x509=NULL;
		const EVP_MD *cert_id_md = NULL;

		unsigned char *p_ocsp_resp = NULL, *p = NULL, *p_ocsp_resp2 = NULL;
		typedef uint8_t    SIGMA_NONCE[32];
		const SIGMA_NONCE* ocspNonce;


		pkey = (EVP_PKEY *)load_key(OCSP_KEY, sizeof(OCSP_KEY));
		if(pkey == NULL)
		{
				printf("Unable to load key\n");
		}
		mkcert(&x509, &pkey, 1 /*serial*/, 365 /*days*/);


		printf("-----------------------------------------------------------------------DAS ----- print x509\n");
		PEM_write_X509(stdout,x509);
		printf("-----------------------------------------------------------------------DAS ----- print x509\n");
		X509_print_fp(stdout,x509);

		dump_to_disk(x509);


		X509_free(x509);
		EVP_PKEY_free(pkey);

		return 0;
}
