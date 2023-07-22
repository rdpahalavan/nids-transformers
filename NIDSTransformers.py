import os
import torch
import pandas as pd
from scapy.all import Ether, CookedLinux
from BERTSimilar import SimilarWords
import pickle
import numpy as np
import importlib.resources
import re
import tempfile
import shutil
import string
try:
    ipython = get_ipython()
    from tqdm.notebook import tqdm as tqdms
except:
    from tqdm import tqdm as tqdms
from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM
from peft import PeftConfig, PeftModel
from sklearn.metrics.pairwise import euclidean_distances


class PADEC:
    def __init__(self, tags=True, text=True):
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.scaler_col_names = [str(i) for i in range(768)]
        self.packet = None
        self.tags = None
        self.payload_hex = None
        if tags:
            with importlib.resources.open_binary('nids_transformers', 'SCALER.pkl') as f:
                self.scaler = pickle.load(f)
            with importlib.resources.open_text('nids_transformers', 'CORPUS.txt') as f:
                temp_fd, temp_path = tempfile.mkstemp(suffix=".txt")
                with open(temp_path, 'w') as tmp:
                    shutil.copyfileobj(f, tmp)
            self.similar = SimilarWords(model='rdpahalavan/bert-network-packet-flow-header-payload',
                                        max_document_length=375, exclude_stopwords=['dos'],
                                        embeddings_scaler=self.scaler).load_dataset(dataset_path=temp_path)
            os.close(temp_fd)
            os.remove(temp_path)
            with importlib.resources.open_binary('nids_transformers', 'KMEANS-CLUSTER-CENTERS.npy') as f:
                self.cluster_centers = np.load(f)
            with importlib.resources.open_binary('nids_transformers', 'TAGS-NAMES-EMBEDDINGS.npy') as f:
                self.tag_names = np.load(f)
        if text:
            for i in tqdms(range(1), unit=' it', desc='Provisioning', postfix='Text Generation Model'):
                PEFT_MODEL = 'rdpahalavan/falcon-adapter-network-packet'
                config = PeftConfig.from_pretrained(PEFT_MODEL)
                self.model = AutoModelForCausalLM.from_pretrained(
                    config.base_model_name_or_path,
                    torch_dtype=torch.bfloat16,
                    return_dict=True,
                    device_map='auto',
                    trust_remote_code=True
                )
                self.tokenizer = AutoTokenizer.from_pretrained(PEFT_MODEL)
                self.tokenizer.pad_token = self.tokenizer.eos_token
                self.model = PeftModel.from_pretrained(self.model, PEFT_MODEL)

    def GenerateTags(self, packet_hex_stream=None, forward_packets_per_second=0, backward_packets_per_second=0,
                     bytes_transferred_per_second=0, total_tags=10, context_similarity_factor=0, output_words_ngram=0,
                     uncased_lemmatization=True, single_word_split=False, output_filter_factor=1):
        packet_bytes = bytes.fromhex(packet_hex_stream)
        packet = Ether(packet_bytes)
        self.packet = packet
        if packet.firstlayer().name != 'Ethernet':
            packet = CookedLinux(packet_bytes)
            if packet.firstlayer().name != 'cooked linux':
                raise ValueError(
                    f"{packet.firstlayer().name} frame not implemented. Ethernet and Cooked Linux are only supported.")
        if packet.haslayer('TCP'):
            pass
        else:
            raise ValueError("Network Packet is not TCP/IP. This model is trained with TCP/IP packets.")
        source_port = packet['TCP'].sport
        destination_port = packet['TCP'].dport
        IP_len = packet['IP'].len
        IP_ttl = packet['IP'].ttl
        IP_tos = f"0x{str(packet['IP'].tos)}"
        tos_map = {
            '0x0': 0, '0x10': 1, '0x18': 2, '0x2': 3, '0x20': 4,
            '0x28': 5, '0x34': 6, '0x4': 7, '0x40': 8, '0x48': 9,
            '0x60': 10, '0x68': 11, '0x8': 12, '0x88': 13
        }
        IP_tos = tos_map.get(IP_tos, 14)
        TCP_dataofs = packet['TCP'].dataofs
        TCP_flags = str(packet['TCP'].flags)
        flags_map = {'A': 0, 'FA': 1, 'FPA': 2, 'PA': 3}
        TCP_flags = flags_map.get(TCP_flags, 4)
        if packet.haslayer('Raw'):
            payload_hex = packet.load.hex()
            payload_len = len(payload_hex) // 2
        else:
            raise ValueError("Network Packet does not contain a payload. This model is trained with a payload.")
        payload_hex = packet.load.hex()
        self.payload_hex = payload_hex
        payload_len = len(payload_hex) // 2
        payload = [int(payload_hex[i:i + 2], 16) for i in range(0, len(payload_hex), 2)]
        final_format = [forward_packets_per_second, backward_packets_per_second, bytes_transferred_per_second, -1,
                        source_port, destination_port, IP_len, payload_len, IP_ttl, IP_tos, TCP_dataofs, TCP_flags, -1
                        ]
        final_format = final_format + payload[:500]
        final_format = [str(i) for i in final_format]
        final_format = ' '.join(final_format)
        cluster, distance, embedding = self._get_packet_embedding(final_format)
        tags, emb = self.similar.find_similar_words(
            input_embedding=(self.tag_names[cluster] + (embedding - self.cluster_centers[cluster])),
            max_output_words=total_tags, context_similarity_factor=context_similarity_factor,
            output_words_ngram=output_words_ngram, uncased_lemmatization=uncased_lemmatization,
            single_word_split=single_word_split, output_filter_factor=output_filter_factor)
        self.tags = tags
        return tags

    def _get_packet_embedding(self, packet):
        tokens = self.similar.tokenizer(packet, truncation=True, return_tensors='pt').to(0)
        output = self.similar.model(**tokens)
        embedding = output.last_hidden_state[:, 1:-1, :].mean(dim=1).cpu().detach().numpy()
        df = pd.DataFrame(embedding[0].reshape(1, -1), columns=self.scaler_col_names)
        embedding = self.scaler.transform(df)[0]
        euclidean_distance = euclidean_distances(self.cluster_centers, [embedding])
        data = {i: euclidean_distance[i][0] for i in range(len(euclidean_distance))}
        df = pd.DataFrame(list(data.items()), columns=['Cluster', 'Euclidean Distance'])
        df.sort_values(by='Euclidean Distance', inplace=True)
        return int(df.iloc[0]['Cluster']), df.iloc[0]['Euclidean Distance'], embedding

    def GenerateText(self, explain_tags=False, explain_packet=False, max_new_tokens=250, temperature=0):
        if not explain_tags and not explain_packet:
            raise ValueError("Enable either explain_tags or explain_packet")
        generation_config = self.model.generation_config
        generation_config.max_new_tokens = max_new_tokens
        generation_config.temperature = temperature
        generation_config.num_return_sequences = 1
        generation_config.pad_token_id = self.tokenizer.eos_token_id
        generation_config.eos_token_id = self.tokenizer.eos_token_id
        if temperature > 0:
            do_sample = True
        else:
            do_sample = False
        if explain_tags:
            prompt = ', '.join([i for i in self.tags.keys()])
        elif explain_packet:
            packet = self.packet.show(dump=True)
            fields_values = {}
            current_layer = ""
            for line in packet.split("\n"):
                if line.startswith("###[") and "]" in line:
                    current_layer = line.split("]")[0].split("[")[1].strip()
                    fields_values[current_layer] = {}
                elif current_layer != "":
                    matches = re.findall(r"\s+([a-z_]+)\s+=\s+(.+)", line)
                    for match in matches:
                        field_name = match[0]
                        field_value = match[1]
                        fields_values[current_layer][field_name] = field_value
            row = {}
            for layer, fields in fields_values.items():
                for field in fields:
                    column_name = f"{layer} {field}"
                    row[column_name] = fields_values[layer][field]
            flag = 0
            packet_text = ''
            for key, value in row.items():
                if 'load' not in key and 'Ethernet' not in key and 'cooked linux' not in key:
                    if flag == 0:
                        packet_text += key + ': ' + value
                        flag = 1
                    else:
                        packet_text += '. ' + key + ': ' + value
            payload_text = self._hex_to_payload(self.payload_hex)
            prompt = packet_text + payload_text
        encoding = self.tokenizer(prompt, return_tensors="pt").to(self.device)
        with torch.inference_mode():
            outputs = self.model.generate(
                input_ids=encoding.input_ids,
                attention_mask=encoding.attention_mask,
                generation_config=generation_config,
                do_sample=do_sample,
                use_cache=True)
        result = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        result = result.split('###')[1]
        result = result.strip()
        sentences = result.split('. ')
        if sentences[-1][-1] != '.':
            result = '. '.join(sentences[:-1]) + '.'
        return result

    def _hex_to_payload(self, payload_hex):
        payload = bytes.fromhex(payload_hex)
        payload = payload.decode('ascii', errors='ignore')
        payload = ''.join(ch for ch in payload if ch in string.printable)
        payload = payload.replace('\n', '')
        payload = payload.replace('\r', '')
        pattern = re.compile("[a-zA-Z .]+")
        matches = pattern.findall(payload)
        matches = [match for match in matches if match.strip()]
        matches = [match for match in matches if len(match) > 2]
        payload = ' '.join(matches)
        return ". The payload contains these words: " + payload