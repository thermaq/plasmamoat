#!/bin/bash
export PYTHONPATH=`pwd`
python3 ./main.py run &
FLASK_APP=front/front.py flask run -h 0.0.0.0

