#!/bin/bash
set -ex
aclocal -I acscripts --install
automake --foreign -a
autoconf
