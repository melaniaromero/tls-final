#!/bin/bash 

# Date: 03/11/2024
# Author: Ricardo Vega
# This script creates a virtual environment and
# runs the crypto project 2025-1

echo "Hi ${USER} !!!"

dir=${HOME}/Downloads/proyecto-cripto
if [ -d $dir ]; then
    echo "Directorio existe"
    rm -rf $dir   
fi
mkdir -p $dir
cd $dir

git clone https://github.com/melaniaromero/tls-final.git
cd ./tls-final
pwd

#Creando ambiente virtual en python
virtualenv mienv 
source mienv/bin/activate
pip3 install -r requirements2.txt

export FLASK_APP=./app/app.py
export FLASK_ENV=development
flask run

