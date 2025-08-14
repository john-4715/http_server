#ifndef __CERT_TRANSACTION_H__
#define __CERT_TRANSACTION_H__

#include <json/autolink.h>
#include <json/config.h>
#include <json/features.h>
#include <json/forwards.h>
#include <json/json.h>
#include <json/reader.h>
#include <json/value.h>
#include <json/writer.h>
#include <stdio.h>

#include <iostream>
#include <string>
#include <vector>

enum ENUM_HTTP_REQ_TYPE
{
	ENUM_HTTP_REQ_DEF,
	ENUM_HTTP_REQ_CSR,
	ENUM_HTTP_REQ_CHALLENGE,
	ENUM_HTTP_REQ_RENEWCERT
};

typedef struct _CSR_REQ_BODY
{
	std::string csr;
	std::string serialNumber;
	std::string productCode;
} CSR_REQ_BODY;

typedef struct _RENEWCERT_REQ_BODY
{
	std::string csr;
	std::string deviceGuid;
} RENEWCERT_REQ_BODY;

bool parseCSRequest(const std::string &request, CSR_REQ_BODY &reqbody);

bool parseRenewCertRequest(const std::string &request, RENEWCERT_REQ_BODY &reqbody);

std::string BuildCsrRespBody();

std::string BuildChallengeCertRespBody();

std::string BuildRenewCertRespBody();

ENUM_HTTP_REQ_TYPE parseUrl(const char *uri);
#endif