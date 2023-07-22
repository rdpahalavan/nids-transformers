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

You can also pass `context_similarity_factor`=(default: 0), `output_words_ngram`=(default: 0), `uncased_lemmatization`=(default: True), `single_word_split`=(default: False), `output_filter_factor`=(default: 1) to control the generation of tags.

### Generating Text

You can generate a descriptive text explaining the generated tags:

```python
text = padec.GenerateText(explain_tags=True, max_new_tokens=250)
```

You can control the randomness by passing a temperature value from 0 to 1, where 0 means less random and 1 means more random (default is `temperature=0`).

You can also generate a descriptive text explaining the network packet:

```python
text = padec.GenerateText(explain_packet=True, max_new_tokens=250)
```

This function takes the same parameters as the `GenerateText` function for explaining tags.

## Demo

### Input

The following is an example of how to prepare and use data for the PADEC module:

```python
from nids_transformers import PADEC

# Initialize PADEC
padec = PADEC()

# Flow Information (From Wireshark Conversations Window)
forward_packets_per_second = 0
backward_packets_per_second = 4
bytes_transferred_per_second = 5493

# Packet Data in Hexadecimal (From Wireshark Hexadecimal View. Copy as Hex Stream)
packet_hex = "3ca6f60849b920b39957e74b0800450005c881dc0000f506c2790d235d2b86588b3301bbf95a94eccbfa554bbac980100085d54400000101080abcb794b10c6ab7722057d82613cc2c721b879ef00e6d925bca92a02d529fd587fd8e5a9cb93dd2a405d8315612500d7179cf7c01ca5e18cd137fe2044fe15898d5b42722f9e79bbc7431ce711171aa63a6b779367d745a0b5432fa326e8e7238d15033da601a4bb9c9bea464f6ca54b64698f31493d9da42fa6e0904a15fb1f944b96de8c55909f7e8780be2de10786b0ff623e503f94276a694bbf823686654ebcdafbfce9f5677e3d21ac1d25426a2be1badeadc5f29449a024419bba4d350ce7494563e9dabaa2c405e21a5fc918586193499139bd967d06ad188e8446ce0ddd406a336847bb64e1e70a73aaffdd1fdfc8cddd89b73433fe0fdcfe11dffa208710e0ecec840b632071872bb688353f59740f45d1efec153e2cc2b69f756b871073a8af9ca923eb213df7c1a67f5679d64e3e758394695fa486c32fd43d454bacc5b5f733eb5e28f70d605ff0947cf68e27dd51081b08ee083976d6b6eb277bd5e8787cb80e0bd574b6f6493e626999467e098ec329fd049d7d20ddc18547e2284e5560509692ce6e86fee5ece2997757697279dbbe418c37a86a79829b34cf8cb52e07e389c61373eff20705d8906aa6d98d5169bb316e963c6a85c8a4f5aea12d6e9a5402cb2aacc63be2b5a845bb5be1f416e19764f44b57837a854d233b764cbb8849f49a5c3deb77a0208cb512d973034c36d90870efdbad00c55fc3d85ef76fd275c21cf0cfbd6cf3cebbd0c62d3c4e8cb21a65b0983c1ed24d9f0a2bd1831316d62aeb6ec9e14a998803671b12d4dcf37151b75b69ec28cca72a36f67b5d3ec3f02606f94ebf941c0f705fd3ba39a154dcb20b1929df10c2ced9db7de3f2bfca59528e699591436b605ae5c174e3c3d7a237c72a0cce22d4cc370767d78a7ed485eb5fc96f6ae45e7e3114ecb1aab59acdcc14a7303b4f49484c2b834f8289e006bd4c6ae38018db9c48ea09caa095b25a0e626486713e07ca409ff52918d6bd390903db3b3a5f823cb91dab2d515c34f459c58dd242529322bc10428786451bd7c2d899f0398c9ffc37302b0d2dca95569d29db478705ed7c85a27ec00cb827c4671424ee33a49a80ec1e63b3a810af84ea42bdac72b6c9a5aa5438bdc4461a9bf3dafc676457072918c6c6a65aaed79a1be272f006edf7c2e930919a53a2eae0749d98cdd9c1b482d4db4adb7a9865ac613bb9a9d8110a72f3f4f40a58fe9fa8eec36e1eee61124d84e92001c617fb025e48e250a173e031552575b48e67d67c988c432364e945e5b3845d61090ccbb628504aac0d453a91c75fa23d6d59b65eadfe79c10f9878715780b9c5b68df37234ddd723b0023611c647f17fddaf0266eec2faa7e745fb06017cbcba1608fd3a9903036d3c5505a3185d0b31f512106509a4cc5582fe13283a18d817b95feb25a61782f2a571722c24979fb39efaf823be465483271e4c4dcc39a8cbc930492ed1b224aa37c50dc19e67b4f1117f92d0bd6ef81cbc72ac2189e27d893b838a19d7a2b8a9b46a6786fdbcfa3749cf564b0038440418a7c9fe2f477458ef743270aeafe0bf510f043a7e7d54787ab92ba80f97d75e06f4bc25cb521d54d221fd089d408d7c9166268376c5c2de1c2f44dc6c0402c35a0f55b2f3ea13f80a11a80f65d41bcb63dac7ae9cfa063a8c749231d6d2cd9b5a83252972f0dd424efa79b72bf558d1648dd2c78c202e7398eef6b8adeab334227e92534e7f3dd26bdaa856ce1feba77f87005e4ed87a6dae4c2bb2c72eecfaaf9e1299cb2f0ff1f3f8cff459e30396bf595d7c08a9a704a394211cc459e01a939cb6cbf8627ceefebb1b338d47079e3958009d2388b86e38a9a5c51f2134c304f98c21d00951c8aa15d3f47e9ba61fa43606d91698000bb7427365ef8b485d11bcdfcea0d52e40af2b76e9f3d372b15c9463b18660f23cd5f04e660f727467a34d8994b22f713f1bfaaf2cb1a0b2aaaa3b1caacd6955ec3e96fde2ca82b5caedc45521cb3978a7c3d65b4076ec96f069608"

# Generate 10 Tags
tags = padec.GenerateTags(packet_hex_stream=packet_hex,
                          forward_packets_per_second=forward_packets_per_second,
                          backward_packets_per_second=backward_packets_per_second,
                          bytes_transferred_per_second=bytes_transferred_per_second,
                          total_tags=10)

print(tags)

tags_text = padec.GenerateText(explain_tags=True, max_new_tokens=250)

print(tags_text)

packet_text = padec.GenerateText(explain_packet=True, max_new_tokens=250)

print(packet_text)
```

### Output

```
# tags
{
  'considered regular expected': 0.9683609588041633,  
  'malicious intent': 0.9615794189652873,  
  'typical': 0.961300843268933,  
  'reference point': 0.9590238971149821,  
  'label signifies normal network behavior': 0.9575988655384243,  
  'standard network protocols': 0.9566183076210247,  
  'baseline': 0.9542804079487445,  
  'Average': 0.9535212932036061,  
  'abnormal traffic patterns enabling': 0.9528368377318245,  
  'expected traffic patterns': 0.952349645227717
}

# tags_text
Based on the majority of the tags, the network packet appears to be a normal packet. It is considered regular and expected, with typical behavior and standard network protocols. The label signifies normal network behavior, and the packet follows expected traffic patterns. There is no indication of malicious intent or abnormal traffic patterns. Overall, it is a regular and normal packet. However, further analysis may be required to ensure its security.

# packet_text
This network packet is an IPv4 packet with a length of 1480 bytes. The packet has a Time-to-Live (TTL) value of 245, indicating that it has been forwarded through 245 routers. The packet is using the TCP protocol and has a source IP address of 13.35.93.43 and a destination IP address of 134.88.139.51. The source port is 443 and the destination port is 63834. The packet has the ACK flag set, indicating that it is acknowledging a previous packet. The payload of the packet contains various words and phrases, such as "VPqy," "qqcy," "KdTFBn," and "DmY." These words do not provide much context or meaning, but they could be part of a message or data being transmitted. Overall, there are no abnormalities in the packet, and it appears to be a normal TCP packet with a specific payload. However, further analysis would be required to determine if any security issues or anomalies are present. The packet does not exhibit any suspicious or malicious behavior. The IP version is 4, indicating that it is an IPv4 packet.
```

## Notes

It's recommended to ensure you have sufficient disk space and RAM when using this package.
