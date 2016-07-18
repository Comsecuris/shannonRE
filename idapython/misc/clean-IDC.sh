#!/bin/bash
# © Copyright 2015/2016 Comsecuris UG

IDC="$1"
OIDC="$2"


function remove_comments {
    grep -v '^//' "$1"
}

function remove_filenames {
    grep -v 'ExtLinA.*File Name' "$1"
}

function remove_somethings {
    grep -v 'MakeName.*".*_something[_"0-9]*' "$1"
}

function remove_wipe {
    grep -v 'DeleteAll' "$1"
}

if [ $# -ne 2 ]; then
    echo "$0 <in> <out>"
    exit 2
fi

TMPIDC="$(mktemp /tmp/fooXXXXXX)"
cp $IDC $TMPIDC

remove_comments $TMPIDC > $OIDC  ; cp $OIDC $TMPIDC
remove_filenames $TMPIDC > $OIDC ; cp $OIDC $TMPIDC
remove_somethings $TMPIDC > $OIDC ; cp $OIDC $TMPIDC
remove_wipe $TMPIDC > $OIDC ; cp $OIDC $TMPIDC

rm $TMPIDC
