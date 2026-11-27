"""Evidence-only collection order for the matched A2 Merak runs."""

import os
import random

import pytest


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(items):
    items.sort(key=lambda item: item.nodeid)
    random.Random(int(os.environ["AWEB_A2_ORDER_SEED"])).shuffle(items)
