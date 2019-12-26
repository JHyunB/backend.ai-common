from typing import Any as _Any
from .base import Trafaret, Key


class ConstructMeta(type):
    def __or__(self, other): ...
    def __and__(self, other): ...

class C(object, metaclass=ConstructMeta): ...

def construct(arg: _Any) -> Trafaret: ...
def construct_key(key: _Any) -> Key: ...