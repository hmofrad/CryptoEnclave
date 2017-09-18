#!/bin/bash
# Committing made easy
# Working with origin remote repository and master branch 
# ./gitty FILE_TO_COMMIT ["COMMIT_COMMENTS"]
# (c) Mohammad Hasanzadeh-Mofrad, 2017
# (e) mohammad.hmofrad@pitt.edu

# To setup under a Linux box after git clone REPO_ADDRESS
# git config --global user.email EMAIL
# git config --system user.email EMAIL
# git config --local  user.email EMAIL

if [ -z "$1" ] || [ $# -gt 2 ]; then
    echo "Usage: ./gitty.sh <FILE|FLAG> [\"COMMENT\"]";
    echo "FLAGS (git v2.x):"
    echo "   .                  : Stage all (new, modified, deleted) files"
    echo "   --all              : Stage all (new, modified, deleted) files"
    echo "   --ignored-removal .: Stage new and modified files"
    echo "   --update           : Stage modified and deleted files"
    exit 1;
fi

FILE=$1
COMMENT=$2
# Disable gnome-ssh-askpass
unset SSH_ASKPASS;
# File to commit
git add $FILE;
# Now commit the change
git commit -m "Update $FILE $COMMENT";
# Push the commit to master branch
git push origin master;
