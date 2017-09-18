#!/bin/bash

wget -i url.txt

F1="20417.txt.utf-8"
F2="4300-0.txt"
F3="5000-8.txt"
cp $F1 file1.txt;
cp $F2 file2.txt;
cp $F3 file3.txt;

for i in {1..3};do
   cat file1.txt file1.txt  > file11.txt;
   cat file2.txt file2.txt  > file22.txt;
   cat file3.txt file3.txt  > file33.txt;
   cat file11.txt file22.txt file33.txt >> out.txt;
done

rm -rf file*
