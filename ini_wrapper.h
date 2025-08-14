#ifndef INI_WRAPPER_H
#define INI_WRAPPER_H

#include <iniparser/iniparser.h>

// INI 配置句柄
typedef dictionary ini_config;

// 函数声明
ini_config *ini_load(const char *filename);
int ini_save(ini_config *config, const char *filename);
void ini_free(ini_config *config);

// 读取函数
const char *ini_get_string(ini_config *config, const char *section, const char *key, const char *default_value);
int ini_get_int(ini_config *config, const char *section, const char *key, int default_value);
double ini_get_double(ini_config *config, const char *section, const char *key, double default_value);
int ini_get_boolean(ini_config *config, const char *section, const char *key, int default_value);

// 写入函数
void ini_set(ini_config *config, const char *section, const char *key, const char *value);

// 工具函数
int ini_has_section(ini_config *config, const char *section);
int ini_has_key(ini_config *config, const char *section, const char *key);
void ini_remove_key(ini_config *config, const char *section, const char *key);

#endif // INI_WRAPPER_H