# flake8: noqa

from re import *


try:
    Pattern  # >= 3.7
except NameError:
    Pattern = type(compile(''))


try:
    Match  # >= 3.7
except NameError:
    Match = type(compile('').match(''))
