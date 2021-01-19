from network.ByteArray import ByteArray
from network.Message import Message

from typing import List
from threading import Thread
from pyshark import FileCapture


class PacketSniffer(Thread):
    def __init__(self):
        Thread.__init__(self)
        self._messages: List[Message] = []
        self._is_split: bool = False
        self._current_message_id: int = -1
        self._current_message_instance_id: int = -1
        self._current_message_size: int = -1
        self._current_message_data: ByteArray = ByteArray(bytes())
        # self._capture: LiveCapture = LiveCapture('enp0s31f6', bpf_filter='tcp port 5555')
        self._capture: FileCapture = FileCapture('assets/port-5555.pcap')

    def get_messages(self) -> List[Message]:
        return self._messages

    def run(self) -> None:
        for pkt in list(self._capture)[:100]:
            if 'payload' in dir(pkt.tcp):

                print()
                raw_data: bytes = bytes.fromhex(str(pkt.tcp.payload).replace(':', ''))

                ba: ByteArray = ByteArray(raw_data)

                # read sequentially the TCP segment
                while ba.size() > 0:

                    print(f"Segment payload size : {ba.size()}")

                    # the message started in the previous segment
                    if self._is_split:

                        print("Started in the previous segment")

                        # the message continues in the next segment
                        if self._current_message_size > ba.size():
                            print("Message continues in the next segment")
                            self._current_message_data += ba.read_n_bytes(
                                ba.size())  # ByteArray is now empty, will exit the while loop

                        # the message ends in this segment
                        else:
                            print("Message ends in this segment")
                            self._current_message_data += ba.read_n_bytes(
                                self._current_message_size - self._current_message_data.size())

                            # create a new message
                            if str(pkt.tcp.port) != "5555":
                                emitter_string: str = "client"
                            else:
                                emitter_string: str = "server"
                            message: Message = Message(self._current_message_id, self._current_message_data,
                                                       emitter_string)

                            self._messages.append(message)
                            print(message)

                            # reset the current message information
                            self._is_split = False
                            self._current_message_id = -1
                            self._current_message_instance_id = -1
                            self._current_message_size = -1
                            self._current_message_data = ByteArray(bytes())

                    # this is a new message
                    else:

                        print("Started in this segment")

                        hi_header: int = ba.read_short()
                        message_id: int = hi_header >> 2
                        length_type: int = hi_header & 0b11
                        length: int = 0
                        instance_id: int = -1

                        if int(pkt.tcp.port) != 5555:
                            # sent by the client
                            instance_id = ba.read_int()

                        # length
                        if length_type == 0:
                            length = 0
                        elif length_type == 1:
                            length = ba.read_byte()
                        elif length_type == 2:
                            length = ba.read_short()
                        elif length_type == 3:
                            length = ba.read_short() << 8 + ba.read_byte()

                        print(
                            f"Message info \t message_id : {message_id} \t length_type : {length_type} \t length : {length} \t instance_id : {instance_id}")

                        # message continues in the next segment
                        if length > ba.size():
                            print("Message continues in the next segment")
                            self._is_split = True
                            self._current_message_id = message_id
                            self._current_message_size = length
                            self._current_message_instance_id = instance_id
                            self._current_message_data = ba.read_n_bytes(ba.size())

                        # message ends in this segment
                        else:
                            print("Message ends in this segment")
                            # create a new message
                            if str(pkt.tcp.port) != "5555":
                                emitter_string: str = "client"
                            else:
                                emitter_string: str = "server"
                            message: Message = Message(message_id, ByteArray(bytes(ba.read_n_bytes(length))),
                                                       emitter_string, instance_id)
                            self._messages.append(message)
                            print(message)

                print(f"Segment payload size : {ba.size()}")
