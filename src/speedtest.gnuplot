#!/usr/bin/env gnuplot

set terminal pdf dashed size 5.0, 4.0
set output 'speedtest.pdf'

set xrange [10:1600000]
set format x "%.0f"

### Plot ###

set title "libgcrypt Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0 lt 1 lc 1, \
     "gcrypt-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0 lt 1 lc 2, \
     "gcrypt-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0 lt 1 lc 3, \
     "gcrypt-camellia-ecb.txt" using 1:2:3 title "Camellia" with errorlines pointtype 0 lt 1 lc 4, \
     "gcrypt-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0 lt 1 lc 5, \
     "gcrypt-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0 lt 1 lc 6, \
     "gcrypt-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0 lt 1 lc 7

### Plot ###

set title "libgcrypt Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines lt 1 lc 1, \
     "gcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines lt 1 lc 2, \
     "gcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines lt 1 lc 3, \
     "gcrypt-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "Camellia" with lines lt 1 lc 4, \
     "gcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines lt 1 lc 5, \
     "gcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines lt 1 lc 6, \
     "gcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines lt 1 lc 7

### Plot ###

set title "libmcrypt Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "mcrypt-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0 lt 1 lc 2, \
     "mcrypt-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0 lt 1 lc 3, \
     "mcrypt-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0 lt 1 lc 4, \
     "mcrypt-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0 lt 1 lc 5, \
     "mcrypt-saferplus-ecb.txt" using 1:2:3 title "Safer+" with errorlines pointtype 0 lt 1 lc 6, \
     "mcrypt-loki97-ecb.txt" using 1:2:3 title "Loki97" with errorlines pointtype 0 lt 1 lc 7, \
     "mcrypt-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0 lt 1 lc 8, \
     "mcrypt-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0 lt 1 lc 9, \
     "mcrypt-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0 lt 1 lc 10, \
     "mcrypt-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0 lt 1 lc 11

### Plot ###

set title "libmcrypt Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "mcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines lt 1 lc 1, \
     "mcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines lt 1 lc 2, \
     "mcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines lt 1 lc 3, \
     "mcrypt-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines lt 1 lc 4, \
     "mcrypt-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines lt 1 lc 5, \
     "mcrypt-saferplus-ecb.txt" using 1:($1 / $2) / 1048576 title "Safer+" with lines lt 1 lc 6, \
     "mcrypt-loki97-ecb.txt" using 1:($1 / $2) / 1048576 title "Loki97" with lines lt 1 lc 7, \
     "mcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines lt 1 lc 8, \
     "mcrypt-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines lt 1 lc 9, \
     "mcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines lt 1 lc 10, \
     "mcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines lt 1 lc 11

### Plot ###

set title "Botan Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "botan-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0 lt 1 lc 1, \
     "botan-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0 lt 1 lc 3, \
     "botan-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0 lt 1 lc 4, \
     "botan-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0 lt 1 lc 5, \
     "botan-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0 lt 1 lc 6, \
     "botan-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0 lt 1 lc 7, \
     "botan-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0 lt 1 lc 8, \
     "botan-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0 lt 1 lc 9

### Plot ###

set title "Botan Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "botan-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines lt 1 lc 1, \
     "botan-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines lt 1 lc 2, \
     "botan-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines lt 1 lc 3, \
     "botan-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines lt 1 lc 4, \
     "botan-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines lt 1 lc 5, \
     "botan-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines lt 1 lc 6, \
     "botan-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines lt 1 lc 7, \
     "botan-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines lt 1 lc 8, \
     "botan-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines lt 1 lc 9

### Plot ###

set title "Crypto++ Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "cryptopp-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0 lt 1 lc 1, \
     "cryptopp-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0 lt 1 lc 2, \
     "cryptopp-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0 lt 1 lc 4, \
     "cryptopp-camellia-ecb.txt" using 1:2:3 title "Camellia" with errorlines pointtype 0 lt 1 lc 5, \
     "cryptopp-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0 lt 1 lc 6, \
     "cryptopp-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0 lt 1 lc 7, \
     "cryptopp-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0 lt 1 lc 8, \
     "cryptopp-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0 lt 1 lc 9, \
     "cryptopp-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0 lt 1 lc 10

### Plot ###

set title "Crypto++ Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "cryptopp-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines lt 1 lc 1, \
     "cryptopp-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines lt 1 lc 2, \
     "cryptopp-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines lt 1 lc 3, \
     "cryptopp-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines lt 1 lc 4, \
     "cryptopp-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "Camellia" with lines lt 1 lc 5, \
     "cryptopp-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines lt 1 lc 6, \
     "cryptopp-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines lt 1 lc 7, \
     "cryptopp-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines lt 1 lc 8, \
     "cryptopp-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines lt 1 lc 9, \
     "cryptopp-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines lt 1 lc 10

### Plot ###

set title "OpenSSL Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "openssl-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0 lt 1 lc 1, \
     "openssl-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0 lt 1 lc 2, \
     "openssl-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0 lt 1 lc 3, \
     "openssl-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0 lt 1 lc 4

### Plot ###

set title "OpenSSL Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "openssl-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines lt 1 lc 1, \
     "openssl-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines lt 1 lc 2, \
     "openssl-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines lt 1 lc 3, \
     "openssl-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines lt 1 lc 4

### Plot ###

set title "Rijndael AES: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-rijndael-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-rijndael-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-rijndael-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4, \
     "openssl-rijndael-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0 lt 1 lc 5

### Plot ###

set title "Rijndael AES: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4, \
     "openssl-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines lt 1 lc 5

### Plot ###

set title "Serpent: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-serpent-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-serpent-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-serpent-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-serpent-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4

### Plot ###

set title "Serpent: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4

### Plot ###

set title "Twofish: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-twofish-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-twofish-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-twofish-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-twofish-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4

### Plot ###

set title "Twofish: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4

### Plot ###

set title "Blowfish: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-blowfish-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-blowfish-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-blowfish-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-blowfish-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4, \
     "openssl-blowfish-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0 lt 1 lc 5

### Plot ###

set title "Blowfish: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4, \
     "openssl-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines lt 1 lc 5

### Plot ###

set title "CAST5: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-cast5-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-cast5-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-cast5-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-cast5-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4, \
     "openssl-cast5-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0 lt 1 lc 5

### Plot ###

set title "CAST5: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4, \
     "openssl-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines lt 1 lc 5

### Plot ###

set title "Triple DES: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-3des-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0 lt 1 lc 1, \
     "mcrypt-3des-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0 lt 1 lc 2, \
     "botan-3des-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0 lt 1 lc 3, \
     "cryptopp-3des-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0 lt 1 lc 4, \
     "openssl-3des-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0 lt 1 lc 5

### Plot ###

set title "Triple DES: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines lt 1 lc 1, \
     "mcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines lt 1 lc 2, \
     "botan-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines lt 1 lc 3, \
     "cryptopp-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines lt 1 lc 4, \
     "openssl-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines lt 1 lc 5
