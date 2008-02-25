#!/usr/bin/env gnuplot

set terminal pdf solid size 5.0, 3.5
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

plot "gcrypt-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0, \
     "gcrypt-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0, \
     "gcrypt-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0, \
     "gcrypt-camellia-ecb.txt" using 1:2:3 title "Camellia" with errorlines pointtype 0, \
     "gcrypt-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0, \
     "gcrypt-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0, \
     "gcrypt-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0

### Plot ###

set title "libgcrypt Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines, \
     "gcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines, \
     "gcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines, \
     "gcrypt-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "Camellia" with lines, \
     "gcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines, \
     "gcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines, \
     "gcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines

### Plot ###

set title "libmcrypt Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "mcrypt-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0, \
     "mcrypt-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0, \
     "mcrypt-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0, \
     "mcrypt-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0, \
     "mcrypt-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0, \
     "mcrypt-saferplus-ecb.txt" using 1:2:3 title "Safer+" with errorlines pointtype 0, \
     "mcrypt-loki97-ecb.txt" using 1:2:3 title "Loki97" with errorlines pointtype 0, \
     "mcrypt-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0, \
     "mcrypt-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0, \
     "mcrypt-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0, \
     "mcrypt-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0

### Plot ###

set title "libmcrypt Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "mcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines, \
     "mcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines, \
     "mcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines, \
     "mcrypt-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines, \
     "mcrypt-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines, \
     "mcrypt-saferplus-ecb.txt" using 1:($1 / $2) / 1048576 title "Safer+" with lines, \
     "mcrypt-loki97-ecb.txt" using 1:($1 / $2) / 1048576 title "Loki97" with lines, \
     "mcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines, \
     "mcrypt-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines, \
     "mcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines, \
     "mcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines

### Plot ###

set title "Botan Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "botan-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0, \
     "botan-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0, \
     "botan-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0, \
     "botan-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0, \
     "botan-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0, \
     "botan-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0, \
     "botan-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0, \
     "botan-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0, \
     "botan-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0

### Plot ###

set title "Botan Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "botan-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines, \
     "botan-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines, \
     "botan-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines, \
     "botan-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines, \
     "botan-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines, \
     "botan-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines, \
     "botan-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines, \
     "botan-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines, \
     "botan-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines

### Plot ###

set title "Crypto++ Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "cryptopp-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0, \
     "cryptopp-serpent-ecb.txt" using 1:2:3 title "Serpent" with errorlines pointtype 0, \
     "cryptopp-twofish-ecb.txt" using 1:2:3 title "Twofish" with errorlines pointtype 0, \
     "cryptopp-cast6-ecb.txt" using 1:2:3 title "CAST6" with errorlines pointtype 0, \
     "cryptopp-camellia-ecb.txt" using 1:2:3 title "Camellia" with errorlines pointtype 0, \
     "cryptopp-gost-ecb.txt" using 1:2:3 title "GOST" with errorlines pointtype 0, \
     "cryptopp-xtea-ecb.txt" using 1:2:3 title "xTEA" with errorlines pointtype 0, \
     "cryptopp-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0, \
     "cryptopp-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0, \
     "cryptopp-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0

### Plot ###

set title "Crypto++ Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "cryptopp-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines, \
     "cryptopp-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Serpent" with lines, \
     "cryptopp-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Twofish" with lines, \
     "cryptopp-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST6" with lines, \
     "cryptopp-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "Camellia" with lines, \
     "cryptopp-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "GOST" with lines, \
     "cryptopp-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "xTEA" with lines, \
     "cryptopp-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines, \
     "cryptopp-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines, \
     "cryptopp-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines

### Plot ###

set title "OpenSSL Ciphers: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "openssl-rijndael-ecb.txt" using 1:2:3 title "Rijndael" with errorlines pointtype 0, \
     "openssl-blowfish-ecb.txt" using 1:2:3 title "Blowfish" with errorlines pointtype 0, \
     "openssl-cast5-ecb.txt" using 1:2:3 title "CAST5" with errorlines pointtype 0, \
     "openssl-3des-ecb.txt" using 1:2:3 title "3DES" with errorlines pointtype 0

### Plot ###

set title "OpenSSL Ciphers: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "openssl-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Rijndael" with lines, \
     "openssl-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Blowfish" with lines, \
     "openssl-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "CAST5" with lines, \
     "openssl-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "3DES" with lines

### Plot ###

set title "Rijndael AES: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-rijndael-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-rijndael-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-rijndael-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0, \
     "openssl-rijndael-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0, \
     "my-rijndael-ecb.txt" using 1:2:3 title "My" with errorlines pointtype 0

### Plot ###

set title "Rijndael AES: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines, \
     "openssl-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines, \
     "my-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "My" with lines

### Plot ###

set title "Serpent: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-serpent-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-serpent-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-serpent-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-serpent-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0, \
     "gladman-serpent-ecb.txt" using 1:2:3 title "Gladman" with errorlines pointtype 0

### Plot ###

set title "Serpent: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines, \
     "gladman-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Gladman" with lines

### Plot ###

set title "Twofish: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-twofish-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-twofish-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-twofish-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-twofish-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0

### Plot ###

set title "Twofish: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines

### Plot ###

set title "Blowfish: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-blowfish-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-blowfish-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-blowfish-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-blowfish-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0, \
     "openssl-blowfish-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0

### Plot ###

set title "Blowfish: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines, \
     "openssl-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines

### Plot ###

set title "CAST5: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-cast5-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-cast5-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-cast5-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-cast5-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0, \
     "openssl-cast5-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0

### Plot ###

set title "CAST5: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines, \
     "openssl-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines

### Plot ###

set title "Triple DES: Absolute Time by Data Length with Standard Deviation"
set xlabel "Data Length in Bytes"
set ylabel "Seconds"
set logscale x
set logscale y
set key below

plot "gcrypt-3des-ecb.txt" using 1:2:3 title "libgcrypt" with errorlines pointtype 0, \
     "mcrypt-3des-ecb.txt" using 1:2:3 title "libmcrypt" with errorlines pointtype 0, \
     "botan-3des-ecb.txt" using 1:2:3 title "Botan" with errorlines pointtype 0, \
     "cryptopp-3des-ecb.txt" using 1:2:3 title "Crypto++" with errorlines pointtype 0, \
     "openssl-3des-ecb.txt" using 1:2:3 title "OpenSSL" with errorlines pointtype 0

### Plot ###

set title "Triple DES: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot "gcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt" with lines, \
     "mcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt" with lines, \
     "botan-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan" with lines, \
     "cryptopp-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++" with lines, \
     "openssl-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL" with lines

### Plot ###

set terminal pdf dashed linewidth 2.0 size 5.0, 7.07
set output 'speedtest-all.pdf'

set title "All Tests: Speed by Data Length"
set xlabel "Data Length in Bytes"
set ylabel "Megabyte / Second"
set logscale x
unset logscale y
set key below

plot \
     "botan-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan 3DES" with lines lt 2 lc 11, \
     "botan-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan Blowfish" with lines lt 2 lc 10, \
     "botan-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan CAST5" with lines lt 2 lc 9, \
     "botan-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan CAST6" with lines lt 2 lc 4, \
     "botan-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan GOST" with lines lt 2 lc 5, \
     "botan-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan Rijndael" with lines lt 2 lc 1, \
     "botan-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan Serpent" with lines lt 2 lc 2, \
     "botan-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan Twofish" with lines lt 2 lc 3, \
     "botan-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "Botan XTEA" with lines lt 2 lc 8, \
     "cryptopp-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ 3DES" with lines lt 3 lc 11, \
     "cryptopp-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ Blowfish" with lines lt 3 lc 10, \
     "cryptopp-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ Camellia" with lines lt 3 lc 11, \
     "cryptopp-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ CAST5" with lines lt 3 lc 9, \
     "cryptopp-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ CAST6" with lines lt 3 lc 4, \
     "cryptopp-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ GOST" with lines lt 3 lc 5, \
     "cryptopp-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ Rijndael" with lines lt 3 lc 1, \
     "cryptopp-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ Serpent" with lines lt 3 lc 2, \
     "cryptopp-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ Twofish" with lines lt 3 lc 3, \
     "cryptopp-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "Crypto++ XTEA" with lines lt 3 lc 8, \
     "gcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt 3DES" with lines lt 4 lc 11, \
     "gcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt Blowfish" with lines lt 4 lc 10, \
     "gcrypt-camellia-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt Camellia" with lines lt 4 lc 11, \
     "gcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt CAST5" with lines lt 4 lc 9, \
     "gcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt Rijndael" with lines lt 4 lc 1, \
     "gcrypt-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt Serpent" with lines lt 4 lc 2, \
     "gcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libgcrypt Twofish" with lines lt 4 lc 3, \
     "mcrypt-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt 3DES" with lines lt 5 lc 11, \
     "mcrypt-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt Blowfish" with lines lt 5 lc 10, \
     "mcrypt-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt CAST5" with lines lt 5 lc 9, \
     "mcrypt-cast6-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt CAST6" with lines lt 5 lc 4, \
     "mcrypt-gost-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt GOST" with lines lt 5 lc 5, \
     "mcrypt-loki97-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt Loki97" with lines lt 5 lc 6, \
     "mcrypt-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt Rijndael" with lines lt 5 lc 1, \
     "mcrypt-saferplus-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt Safer+" with lines lt 5 lc 7, \
     "mcrypt-twofish-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt Twofish" with lines lt 5 lc 3, \
     "mcrypt-xtea-ecb.txt" using 1:($1 / $2) / 1048576 title "libmcrypt XTEA" with lines lt 5 lc 8, \
     "my-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "my Rijndael" with lines lt 1 lc 1, \
     "gladman-serpent-ecb.txt" using 1:($1 / $2) / 1048576 title "Gladman Serpent" with lines lt 1 lc 2, \
     "openssl-3des-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL 3DES" with lines lt 7 lc 11, \
     "openssl-blowfish-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL Blowfish" with lines lt 7 lc 10, \
     "openssl-cast5-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL CAST5" with lines lt 7 lc 9, \
     "openssl-rijndael-ecb.txt" using 1:($1 / $2) / 1048576 title "OpenSSL Rijndael" with lines lt 7 lc 1