#!/bin/bash


if ! command -v python3 &> /dev/null
then
    echo "Python 3 is not installed. Please install it and try again."
    exit 1
fi


chmod +x hashkiller.py


cp hashkiller.py /usr/local/bin/HashKiller

echo "Installation completed. You can now call your script with 'HashKiller'"
