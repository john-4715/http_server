#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

time_t GetNextDaysTimeStamp(int days)
{
	time_t current_time;
	time(&current_time); // 获取当前UTC时间戳

	struct tm *utc_tm = localtime(&current_time); // 转换为UTC时间结构体
	printf("current time: %s", asctime(utc_tm));

	// 一天后的时间
	utc_tm->tm_mday += days; // 增加一天
	time_t timestamp = mktime(utc_tm);

	printf("证书过期时间是: \n");
	print_time_t(timestamp);

	return timestamp;
}

void print_time_t(time_t t)
{
	char buf[128];
	struct tm *tm_info = localtime(&t);
	strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
	printf("%s\n", buf);
}

time_t getChallengeIDExpireTime()
{
	// 初始化一个 struct tm 结构体来存储日期和时间
	struct tm date;

	// 设置日期
	date.tm_year = 2034 - 1900; // tm_year 是从1900年起的年数
	date.tm_mon = 7 - 1;		// tm_mon 是从0开始的月份，所以7月是6
	date.tm_mday = 15;			// 日
	date.tm_hour = 0;			// 时
	date.tm_min = 0;			// 分
	date.tm_sec = 0;			// 秒
	date.tm_isdst = -1;			// 让 mktime 自动判断夏令时

	// 使用 mktime 将 struct tm 转换为 time_t 类型的时间戳
	time_t timestamp = mktime(&date);

	// 检查转换是否成功
	if (timestamp == -1)
	{
		printf("Error in converting date to timestamp.\n");
		return 1;
	}

	// 打印时间戳
	printf("Timestamp for July 15, 2034 is: %ld\n", timestamp);
	return timestamp;
}

// 从最佳可用源获取随机字节
static void get_random_bytes(unsigned char *buf, size_t len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0)
	{
		read(fd, buf, len);
		close(fd);
	}
	else
	{
		// 后备方案 - 使用时间+pid作为种子
		srand(time(NULL) ^ getpid());
		for (size_t i = 0; i < len; i++)
		{
			buf[i] = rand() % 256;
		}
	}
}

// 生成UUID版本4 (随机)
void generate_uuid_v4(char *uuid_str)
{
	unsigned char bytes[16];
	get_random_bytes(bytes, 16);

	// 设置版本号 (4) 和变体 (10)
	bytes[6] = (bytes[6] & 0x0F) | 0x40; // 版本4
	bytes[8] = (bytes[8] & 0x3F) | 0x80; // 变体1 (RFC 4122)

	// 格式化为UUID字符串
	snprintf(uuid_str, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0], bytes[1],
			 bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
			 bytes[12], bytes[13], bytes[14], bytes[15]);
}
