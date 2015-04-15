#! /bin/bash

zypper lr -u -E -P | awk '{for (i=1;i<=NF;i++) { if ($i ~ /^http/) {print $i} }}'
