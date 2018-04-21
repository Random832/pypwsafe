# Simple smoke test for conversion
export PYTHONPATH=./src:./src/pypwsafe
PATH=./pwsafecli:$PATH
python3 ./pwsafecli/pwsafecli.py test_pwsafecli.py
python3 ./pwsafecli/psafedump -p password -f Test.psafe3
python3 ./pwsafecli/psafedump -p password -f Test.psafe3 --csv
python ./pwsafecli/pwsafecli.py test_pwsafecli.py
python ./pwsafecli/psafedump -p password -f Test.psafe3
python ./pwsafecli/psafedump -p password -f Test.psafe3 --csv
