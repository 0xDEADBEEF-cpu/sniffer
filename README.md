# Сниффер сетевых пакетов с анализом протоколов

[![Python Version](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python)](https://python.org)
[![Scapy Version](https://img.shields.io/badge/Scapy-2.4.5-red)](https://scapy.net)

Мощный инструмент для анализа сетевого трафика с расширенными возможностями визуализации и фильтрации. Захватывает и анализирует пакеты в реальном времени с поддержкой основных сетевых протоколов.
## ✨ Особенности

- Захват трафика на выбранном сетевом интерфейсе
- Анализ основных протоколов:
  - Ethernet (MAC-адреса)
  - IP (адреса источника и назначения)
  - DNS (запросы доменных имен)
  - HTTP (методы и пути запросов)
- Фильтрация трафика по портам 53 (DNS), 80 (HTTP), 443 (HTTPS)
- Консольный вывод результатов в формате JSON

## Требования

- Python 3.6+
- Scapy
- scapy-http (для анализа HTTP)

## 🛠️ Установка

### 🖥️ Linux (Debian/Ubuntu)
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip git -y
git clone https://github.com/0xDEADBEEF-cpu/portscan.git
cd portscan
pip3 install -r requirements.txt
python portscan.py
```
