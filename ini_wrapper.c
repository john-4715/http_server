#include "ini_wrapper.h"
#include <stdlib.h>
#include <string.h>

// 创建完整键名 (section:key)
static char *make_full_key(const char *section, const char *key)
{
	size_t len = strlen(section) + strlen(key) + 2; // +2 for ':' and null terminator
	char *full_key = (char*)malloc(len);
	if (full_key)
	{
		snprintf(full_key, len, "%s:%s", section, key);
	}
	return full_key;
}

// 加载 INI 文件
ini_config *ini_load(const char *filename) { return iniparser_load(filename); }

// 保存 INI 文件
int ini_save(ini_config *config, const char *filename)
{
	FILE *fp = fopen(filename, "w");
	if (!fp)
	{
		return -1;
	}

	iniparser_dump_ini(config, fp);
	fclose(fp);
	return 0;
}

// 释放 INI 配置
void ini_free(ini_config *config)
{
	if (config)
	{
		iniparser_freedict(config);
	}
}

// 获取字符串值
const char *ini_get_string(ini_config *config, const char *section, const char *key, const char *default_value)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return default_value;

	const char *result = iniparser_getstring(config, full_key, default_value);
	free(full_key);
	return result;
}

// 获取整数值
int ini_get_int(ini_config *config, const char *section, const char *key, int default_value)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return default_value;

	int result = iniparser_getint(config, full_key, default_value);
	free(full_key);
	return result;
}

// 获取浮点数值
double ini_get_double(ini_config *config, const char *section, const char *key, double default_value)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return default_value;

	double result = iniparser_getdouble(config, full_key, default_value);
	free(full_key);
	return result;
}

// 获取布尔值
int ini_get_boolean(ini_config *config, const char *section, const char *key, int default_value)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return default_value;

	int result = iniparser_getboolean(config, full_key, default_value);
	free(full_key);
	return result;
}

// 保存原始键名到值中
void iniparser_preserve_case_save(dictionary *dict, const char *key, const char *value)
{
	char preserved_key[256];
	snprintf(preserved_key, sizeof(preserved_key), "_ORIG_%s", key);
	iniparser_set(dict, preserved_key, key); // 保存原始键名
	iniparser_set(dict, key, value);		 // 使用库的标准设置
}

// 获取原始键名
const char *iniparser_preserve_case_get_original_key(dictionary *dict, const char *key)
{
	char preserved_key[256];
	snprintf(preserved_key, sizeof(preserved_key), "_ORIG_%s", key);
	return iniparser_getstring(dict, preserved_key, key);
}

// 写入文件时恢复原始键名
void iniparser_preserve_case_dump(dictionary *dict, FILE *f)
{
	int nsec = iniparser_getnsec(dict);
	for (int i = 0; i < nsec; i++)
	{
		const char *sec = iniparser_getsecname(dict, i);
		fprintf(f, "[%s]\n", sec);

		int nkeys = iniparser_getsecnkeys(dict, sec);
		const char **keylist = NULL; // 先初始化为 NULL
		const char **keys = iniparser_getseckeys(dict, sec, keylist);

		for (int j = 0; j < nkeys; j++)
		{
			// 检查是否是我们的保留键
			if (strncmp(keys[j], "_ORIG_", 6) == 0)
				continue;

			// 尝试获取原始键名
			const char *orig_key = iniparser_preserve_case_get_original_key(dict, keys[j]);
			const char *value = iniparser_getstring(dict, keys[j], NULL);

			if (value)
			{
				fprintf(f, "%s = %s\n", orig_key, value);
			}
		}
		fprintf(f, "\n");
		free(keys);
	}
}

// 设置字符串值
void ini_set(ini_config *config, const char *section, const char *key, const char *value)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return;

	iniparser_set(config, full_key, value);
	free(full_key);
}

// 检查节是否存在
int ini_has_section(ini_config *config, const char *section) { return iniparser_find_entry(config, section) == 1; }

// 检查键是否存在
int ini_has_key(ini_config *config, const char *section, const char *key)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return 0;

	int result = iniparser_find_entry(config, full_key) == 1;
	free(full_key);
	return result;
}

// 删除键
void ini_remove_key(ini_config *config, const char *section, const char *key)
{
	char *full_key = make_full_key(section, key);
	if (!full_key)
		return;

	iniparser_unset(config, full_key);
	free(full_key);
}

