from scapy.all import *

def anonymize_ip(packet):
    if IP in packet:
        packet[IP].src = "0.0.0.0"
        packet[IP].dst = "0.0.0.0"
        del packet[IP].chksum  # Remove o checksum antigo para que o Scapy recalcule
    return packet

def main():
    packets = rdpcap("input.pcap")  # Lê o arquivo input.pcap
    anonymized_packets = [anonymize_ip(packet) for packet in packets]
    wrpcap("output.pcap", anonymized_packets)  # Escreve os pacotes anonimizados no arquivo output.pcap

if __name__ == "__main__":
    main()
