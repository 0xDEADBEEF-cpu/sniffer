# Сниффер сетевых пакетов с анализом протоколов

Простой сетевой сниффер на Python с использованием Scapy для перехвата и анализа Ethernet, IP, DNS и HTTP трафика. Отображает базовую информацию о пакетах в реальном времени.

## Особенности

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
git clone https://github.com/Dimatop228/portscan.git
cd portscan
pip3 install -r requirements.txt
python portscan.py
```
