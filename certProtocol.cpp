#include <stdio.h>
#include <string.h>

#include "certMgr.hpp"
#include "certProtocol.hpp"
#include "utils.h"
#include "json/writer.h"

bool parseCSRequest(const std::string &request, CSR_REQ_BODY &reqbody)
{
	bool bret = false;
	do
	{
		Json::Reader oReader;
		Json::Value oRequest;

		if (oReader.parse(request, oRequest))
		{
			if (oRequest.isMember("csr"))
			{
				reqbody.csr = oRequest["csr"].asString();
			}
			if (oRequest.isMember("serialNumber"))
			{
				reqbody.serialNumber = oRequest["serialNumber"].asString();
			}
			if (oRequest.isMember("productCode"))
			{
				reqbody.productCode = oRequest["productCode"].asString();
			}
			bret = true;
		}
	} while (0);
	return bret;
}

bool parseRenewCertRequest(const std::string &request, RENEWCERT_REQ_BODY &reqbody)
{
	bool bret = false;
	do
	{
		Json::Reader oReader;
		Json::Value oRequest;

		if (oReader.parse(request, oRequest))
		{
			if (oRequest.isMember("csr"))
			{
				reqbody.csr = oRequest["csr"].asString();
			}
			if (oRequest.isMember("deviceGuid"))
			{
				reqbody.deviceGuid = oRequest["deviceGuid"].asString();
			}
			bret = true;
		}
	} while (0);
	return bret;
}

#define POST_BODY_SERIAL_NUMBER "serialNumber"
#define POST_BODY_PRODUCT_CODE "productCode"
#define POST_BODY_CSR "csr"
#define POST_BODY_CHALLID "challengeId"
#define POST_BODY_PINCODE "pin"
#define POST_BODY_EXPIREDATE "expirationDate"
#define POST_BODY_DEVICEGUID "deviceGuid"
#define POST_BODY_CACHAIN "caChain"
#define POST_BODY_ISSUECA "issuingCa"
#define POST_BODY_CERTIFICATE "certificate"
#define POST_BODY_MQTTBROKER "mqttBroker"
#define POST_BODY_HOST "host"
#define POST_BODY_PORT "port"
#define POST_BODY_PROTOCOL "protocol"
#define POST_BODY_PROTOVER "protocolVersion"
#define POST_BODY_AUTHTYPE "authType"
#define POST_BODY_SPARKPLUG "sparkplug"
#define POST_BODY_GROUPID "groupId"
#define POST_BODY_HOSTID "hostId"

std::string BuildRunningRespBody()
{
	Json::Value root;
	root["code"] = 0;
	root["message"] = "http server is running.";
	std::string strOut = root.toString();
	return strOut;
}

std::string BuildCsrRespBody()
{
	Json::Value root;

	// 添加字段到root对象
	root[POST_BODY_CHALLID] = "f22ed8fd-7f2a-4827-9365-e9d5855e915f";
	root[POST_BODY_PINCODE] = "123456";
	root[POST_BODY_EXPIREDATE] = (int)GetNextDaysTimeStamp(2);

	std::string strOut = root.toString();
	return strOut;
}

std::string BuildChallengeCertRespBody()
{
	std::string caChainData;
	std::string signCA;
	std::string certificate;

	read_file_to_memory((const char *)"./output/ca.crt", caChainData);
	read_file_to_memory((const char *)"./output/client.crt", signCA);
	read_file_to_memory((const char *)"./output/client.crt", certificate);

	if (!validCertExpir(certificate))
	{
		printf("[%s %d] The certificate expired!!!\n\n", __func__, __LINE__);
	}

	Json::Value root;
	root[POST_BODY_DEVICEGUID] = "6d1ee0b2-bbcb-4c02-a7f9-55f3838bde79";

	Json::Value array;
	array.append(caChainData);
	root[POST_BODY_CACHAIN] = array;

	root[POST_BODY_ISSUECA] = signCA;
	root[POST_BODY_CERTIFICATE] = certificate;
	root[POST_BODY_EXPIREDATE] = (int)GetNextDaysTimeStamp(365);
	root[POST_BODY_SERIAL_NUMBER] = "123456789";
	Json::Value mqttBroker;

	mqttBroker[POST_BODY_HOST] = "mqtt.alsenseplatform.com";
	mqttBroker[POST_BODY_PORT] = 8883;
	mqttBroker[POST_BODY_PROTOCOL] = "mqtts";
	mqttBroker[POST_BODY_PROTOVER] = "4";
	mqttBroker[POST_BODY_AUTHTYPE] = "mtls";

	root[POST_BODY_MQTTBROKER] = mqttBroker;

	Json::Value sparkplug;
	sparkplug[POST_BODY_PROTOCOL] = "spBv1.0";
	sparkplug[POST_BODY_GROUPID] = "0";
	sparkplug[POST_BODY_HOSTID] = "sparkplug_processor";
	root[POST_BODY_SPARKPLUG] = sparkplug;

	std::string strOut = root.toString();

	return strOut;
}

std::string BuildRenewCertRespBody()
{
	std::string caChainData;
	std::string signCA;
	std::string certificate;

	read_file_to_memory((const char *)"./renewcert/ca.crt", caChainData);
	read_file_to_memory((const char *)"./renewcert/client.crt", signCA);
	read_file_to_memory((const char *)"./renewcert/client.crt", certificate);

	if (!validCertExpir(certificate))
	{
		printf("[%s %d] The certificate expired!!!\n\n", __func__, __LINE__);
	}

	Json::Value root;

	Json::Value array;
	array.append(caChainData);
	root[POST_BODY_CACHAIN] = array;

	root["issuingCa"] = signCA;
	root["certificate"] = certificate;

	root["serialNumber"] = "72:89:6e:f3:7c:38:8d:93:f0:72:2c:71:56:ed:ee:f8:46:23:f1:15";
	root["expirationDate"] = (int)GetNextDaysTimeStamp(1);

	std::string strOut = root.toString();

	return strOut;
}

ENUM_HTTP_REQ_TYPE parseUrl(const char *uri)
{
	ENUM_HTTP_REQ_TYPE type = ENUM_HTTP_REQ_DEF;
	char baseuri[] = "/v1/provisioning/devices/";
	char *pos;

	pos = strstr((char *)uri, baseuri);
	if (pos != NULL)
	{
		char substr[] = "/v1/provisioning/devices/challenges";
		char *pstr = strstr((char *)uri, substr);
		if (pstr != NULL)
		{
			if (strlen(pstr) == strlen(substr))
			{
				return ENUM_HTTP_REQ_CSR;
			}
			else if (strlen(pstr) > strlen(substr))
			{
				return ENUM_HTTP_REQ_CHALLENGE;
			}
		}
		else if (strstr(uri, "certificate-renew"))
		{
			return ENUM_HTTP_REQ_RENEWCERT;
		}
	}
	else
	{
		return ENUM_HTTP_REQ_DEF;
	}

	return type;
}