#ifndef __UTILS_H__
#define __UTILS_H__

#include <iostream>
#include <stdio.h>
#include <string>
#include <time.h>

time_t GetNextDaysTimeStamp(int days);

void print_time_t(time_t t);

time_t getChallengeIDExpireTime();

void generate_uuid_v4(char *uuid_str);
#endif