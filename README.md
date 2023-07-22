# NIDS Transformers

`nids-transformers` is a Python package used for generating tags and descriptive text for network packets. This is part of our research project utilizing transformer models in network security and Network Intrusion Detection Systems (NIDS). We have developed the PADEC (Packet Describer) module that generates tags and text for network packets using BERT and Falcon LLMs (Large Language Models).

## Installation

Install the package with pip:

```shell
pip install nids-transformers
```

## Usage

First, import the PADEC module and initialize the models and tokenizers:

```python
from nids_transformers import PADEC

padec = PADEC()
```

To generate only text, you can pass `text=False`.

### Preparing the Input

Prepare the flow information (from the Wireshark Conversations Window). Use 0 if flow information is not available:

```python
forward_packets_per_second = 0
backward_packets_per_second = 4
bytes_transferred_per_second = 5493
```

Prepare the packet data in hexadecimal (from the Wireshark Hexadecimal View, copy as Hex Stream):

```python
packet_hex = '...'  # your hexadecimal data here
```

### Generating Tags

You can generate tags for a network packet with the `GenerateTags` function:

```python
tags = padec.GenerateTags(packet_hex_stream=packet_hex,
                          forward_packets_per_second=forward_packets_per_second,
                          backward_packets_per_second=backward_packets_per_second,
                          bytes_transferred_per_second=bytes_transferred_per_second,
                          total_tags=10)
```

This will output a dictionary with the generated tags and their corresponding scores.

### Generating Text

You can generate a descriptive text explaining the generated tags:

```python
text = padec.GenerateText(explain_tags=True, max_new_tokens=250)
```

You can control the randomness by passing a temperature value from 0 to 1, where 0 means less random and 1 means more random (default is 0).

You can also generate a descriptive text explaining the network packet:

```python
text = padec.GenerateText(explain_packet=True, max_new_tokens=250)
```

This function takes the same parameters as the `GenerateText` function for explaining tags.

## Contribute

Please feel free to fork this repository, make changes, submit pull requests, or just use the code for your own projects. If you find any bugs or have any feature requests, please open an issue in this repository.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
