from scapy.all import sniff, Ether, IP, TCP, UDP, DNS, DNSQR, get_if_list
from scapy.layers.http import HTTPRequest
import json
import os


def packet_analyzer(packet):
    result = {}

    # Ethernet layer
    if packet.haslayer(Ether):
        result["MAC Source"] = packet[Ether].src
        result["MAC Destination"] = packet[Ether].dst

    # IP layer
    if packet.haslayer(IP):
        result["IP Source"] = packet[IP].src
        result["IP Destination"] = packet[IP].dst

    # DNS layer (только запросы)
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        if packet.haslayer(DNSQR):
            result["DNS Query"] = packet[DNSQR].qname.decode(errors="ignore")

    # HTTP layer
    if packet.haslayer(HTTPRequest):
        result["HTTP Request"] = f"{packet[HTTPRequest].Method.decode()} {packet[HTTPRequest].Path.decode()}"

    # Вывод в консоль для диагностики
    if result:
        print("Captured packet:", result)



def main():
    # Проверка доступных интерфейсов
    print("Available interfaces:", get_if_list())

    # Укажите ваш интерфейс (например, "Ethernet", "Wi-Fi", или оставьте None)
    interface = None  # Замените на "Ethernet" или другой, если нужно

    # Запуск сниффера
    print("Starting packet capture... (Press Ctrl+C to stop)")
    try:
        sniff(
            iface=interface,
            prn=packet_analyzer,
            store=0,
            filter="tcp port 80 or udp port 53 or tcp port 443",  # HTTP, DNS, HTTPS
            count=0
        )
    except Exception as e:
        print(f"Error during sniffing: {e}")


if __name__ == "__main__":
    main()
