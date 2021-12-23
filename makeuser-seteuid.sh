#!/bin/sh

if [ -z $1 ]:
then
    echo "Please specifiy user to promote"
else
    usermod -a -G seteuid $1 && echo "$1 now has seteuid permission"
fi
