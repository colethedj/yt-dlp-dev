# flake8: noqa

from asyncio import *


try:
    run  # >= 3.7
except NameError:
    def run(coro):
        try:
            loop = get_event_loop()
        except RuntimeError:
            loop = new_event_loop()
            set_event_loop(loop)
        loop.run_until_complete(coro)
