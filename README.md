# Advanced Proxy Parser

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Мощный инструмент для сбора и проверки прокси-серверов с открытых источников.

## 🔥 Особенности

- Сбор прокси с 50+ источников
- Многопоточная проверка работоспособности
- Поддержка HTTP/HTTPS/SOCKS4/SOCKS5
- Фильтрация по стране и протоколу
- Измерение скорости работы прокси
- Гибкие настройки через аргументы командной строки
- Подробная статистика

## ⚙️ Установка

1. Клонируйте репозиторий:
```bash
git clone https://github.com/DreamHost666/Proxy-Parser.git
cd proxy-parser
```

2. Установите зависимости:
```bash
   pip install -r requirements.txt
```


🚀 Использование
Базовый запуск:
```bash
python proxy_parser.py
```

Продвинутые параметры:
```bash
python proxy_parser.py \
  --max-workers 150 \
  --timeout 15 \
  --limit 10000 \
  --protocols http https socks5 \
  --countries US DE FR \
  --output proxies.txt \
  --format txt
```


📊 Параметры командной строки

   Параметр	            Описание	             По умолчанию
--max-workers	     Количество потоков	          100
--timeout	         Таймаут проверки (сек)	      10.0
--limit	           Лимит сохранения прокси  	  5000
--protocols      	 Фильтр по протоколам	        Все
--countries	       Фильтр по странам (коды)	    Все
--output	         Выходной файл	proxies.txt
--format	         Формат вывода (txt/json)	    txt


📝 Пример выходных данных
Формат TXT:
45.155.204.123:3128|http|US|120ms
91.210.178.161:8080|https|DE|85ms

Формат JSON:

{
  "address": "45.155.204.123:3128",
  "protocol": "http",
  "latency": 120,
  "country": "United States",
  "countryCode": "US",
  "city": "New York",
  "isp": "Digital Ocean",
  "last_checked": "2023-05-20T12:34:56.789Z"
}
