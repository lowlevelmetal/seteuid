#!/bin/sh

if [ -z $1 ]:
then
    echo "Please specifiy user to demote"
else
    gpasswd -d $1 seteuid && echo "$1 has had seteuid permissions removed"
fi

