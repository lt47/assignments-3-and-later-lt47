#!/bin/bash
FILEDIR=$1
SEARCHSTR=$2
if [ $# -ne 2 ];
then 
   echo "ERROR: Invalid number of arguments.\nTotal number of args should be 2.\n The order of args should be:\n 1) File directory.\n 2) Search string."
   exit 1
elif [ ! -d "$FILEDIR" ];
then
   echo "ERROR: Invalid file path. $FILEDIR does not exist."
   exit 1
else
   X=$(find "$FILEDIR" -type f | wc -l)
   Y=$(grep -r "$SEARCHSTR" "$FILEDIR" 2>/dev/null | wc -l)
   echo "The number of files are $X and the number of matching lines are $Y"
fi
   
