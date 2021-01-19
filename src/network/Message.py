from typing import Tuple, List, Dict
from network import ByteArray
import json

with open("assets/d2_protocol.json", 'r') as f:
    d2_protocol = json.load(f)
message_pairs: List[Tuple] = [(d2_protocol['messages'][elem]['protocolID'], elem) for elem in
                              d2_protocol['messages'].keys()]
message_dict: Dict = dict(message_pairs)


class Message:
    def __init__(self, identifier: int, data: ByteArray, emitter: str, instance_id: int = -1):
        self._id: int = identifier

        if self._id in message_dict.keys():
            self._name = message_dict[self._id]
        else:
            self._name: str = str(identifier)

        self._data: ByteArray = data
        self._size: int = len(data)
        self._emitter: str = emitter
        self._instance_id: int = instance_id

    def __str__(self) -> str:
        return f"<{self._emitter} : {self._name} - length : {self._size}> - instance_id : {self._instance_id}"
