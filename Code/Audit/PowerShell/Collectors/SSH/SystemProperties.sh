#!/bin/bash
echo '####CPUINFO####'
cat /proc/cpuinfo
echo '####MEMINFO####'
cat /proc/meminfo
echo '####DISKINFO####'
df -h