## SETUP

1. install pyenv
  1. `curl https://pyenv.run | bash`
  1. restart shell
  1. run `pyenv which python` to ensure it worked
1. install python 3.7
  1. `pyenv install 3.7.0`
1. install pipenv
  1. `brew install pipenv` OR `pip install --user pipenv`
1. checkout the workshop repo
  1. `git clone https://github.com/summa-tx/riemann-workshop.git`
1. install the workshop dependencies
  1. `pipenv install --python=$(pyenv which python3.7)`

## Workshop Layout

Documentation for riemann tx library: https://summa-tx.github.io/riemann/

1. `crypto.py` - some siple crypto tools
1. `transactions.py` - examples for making and signing basic transactions
1. `inspect.py` - an example block parser that computes simple block stats
1. `htlc.py` - how to build a custom script and spend from it
