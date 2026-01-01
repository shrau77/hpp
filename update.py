import requests
import base64
import re
import os
import sys
from datetime import datetime
from urllib.parse import urlparse
import socket
import geoip2.database
from concurrent.futures import ThreadPoolExecutor

# --- ТВОИ НАСТРОЙКИ (БЕЗ ИЗМЕНЕНИЙ) ---
TARGET_SNI = [
    "unicreditbank.ru", "gazprombank.ru", "gpb.ru", "mkb.ru", "open.ru", "tbank.ru", 
    "rosbank.ru", "psbank.ru", "raiffeisen.ru", "rzd.ru", "dns-shop.ru", "pochta.ru", 
    "x5.ru", "ivi.ru", "hh.ru", "kp.ru", "ria.ru", "lenta.ru", "rambler.ru", "rbc.ru", 
    "yandex.net", "pikabu.ru", "tutu.ru", "apteka.ru", "drom.ru", "farpost.ru", 
    "drive2.ru", "lemanapro.ru", "vk-portal.net", "userapi.com", "vk.com", "mail.ru", 
    "ozone.ru", "ozon.ru", "sberbank.ru", "wildberries.ru", "alfabank.ru", "tinkoff.ru", 
    "mts.ru", "megafon.ru", "t2.ru", "beeline.ru", "dzen.ru", "avito.ru", "rutube.ru", 
    "kinopoisk.ru", "magnit.com", "2gis.ru", "ok.ru", "yandex.ru"
]

urls = [
    "https://etoneya.a9fm.site/", "https://etoneya.a9fm.site/2",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS+All_RUS.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://sub-aggregator.vercel.app/"
]
for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

# --- ИНИЦИАЛИЗАЦИЯ GEOIP ---
GEOIP_DB_PATH = 'GeoLite2-Country.mmdb'
reader = None
if os.path.exists(GEOIP_DB_PATH):
    reader = geoip2.database.Reader(GEOIP_DB_PATH)

geo_cache = {}
dns_cache = {}

def get_country_code(node):
    """Оригинальная логика определения с кэшированием DNS"""
    try:
        parsed = urlparse(node)
        host = parsed.netloc.split('@')[-1].split(':')[0]
        
        if host in geo_cache: return geo_cache[host]

        # DNS Резолвинг
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ip = host
        else:
            if host not in dns_cache:
                dns_cache[host] = socket.gethostbyname(host)
            ip = dns_cache[host]

        if reader:
            response = reader.country(ip)
            code = response.country.iso_code
            geo_cache[host] = code
            return code
    except: pass
    return "RU" if ".ru" in node.lower() else "UN"

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ТВОИ ВЕСА) ---

def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def get_flag(code):
    if not code or code in ["UN", "??"]: return "🌐"
    return "".join(chr(ord(c.upper()) + 127397) for c in code)

def calculate_score(config):
    score = 0
    c_l = config.lower()
    if 'xtls-rprx-vision' in c_l: score += 120
    if 'reality' in c_l: score += 80
    if 'pbk=' in c_l: score += 60
    sni_match = re.search(r'(?:sni|peer)=([^&?#]+)', c_l)
    if sni_match:
        found_sni = sni_match.group(1)
        if any(tsni in found_sni for tsni in TARGET_SNI):
            score += 100
    elif any(tsni in c_l for tsni in TARGET_SNI):
        score += 40
    return score

# --- СБОР ---

all_nodes = []
unique_map = {}

log(f"Сбор из {len(urls)} источников...")
for url in urls:
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200: continue
        content = r.text
        if "://" not in content[:100] and len(content) > 20:
            try:
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass
        for line in content.splitlines():
            line = line.strip()
            if "://" in line and not line.startswith("//"):
                key = line.split('#')[0]
                if key not in unique_map:
                    unique_map[key] = line
                    all_nodes.append(line)
    except: pass

log(f"Сортировка {len(all_nodes)} конфигов по качеству...")
all_nodes.sort(key=calculate_score, reverse=True)

# --- ГЕНЕРАЦИЯ (МАКСИМАЛЬНОЕ УСКОРЕНИЕ) ---

def finalize_and_save(filename, data, tag="", limit=None):
    if limit: data = data[:limit]
    if not data: return

    # Запускаем GeoIP в 50 потоков
    with ThreadPoolExecutor(max_workers=50) as executor:
        countries = list(executor.map(get_country_code, data))
    
    output = []
    for i, (node, country) in enumerate(zip(data, countries)):
        node_id = f"{i+1:05}"
        flag = get_flag(country)
        base_link = node.split('#')[0]
        # Сохраняем твой формат нейминга
        new_name = f"{flag} {tag}{country}-{node_id}-HPP"
        output.append(f"{base_link}#{new_name}")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    log(f"💾 {filename} сохранен ({len(output)} строк)")

# --- СОХРАНЕНИЕ ВСЕХ ТВОИХ СПИСКОВ ---

finalize_and_save("sub.txt", all_nodes, limit=10000)
finalize_and_save("sub_lite.txt", all_nodes, limit=1000)
finalize_and_save("shadowsocks.txt", [n for n in all_nodes if n.startswith("ss://")], limit=2000)
finalize_and_save("vless_vmess.txt", [n for n in all_nodes if not n.startswith("ss://")], limit=5000)

# Твой Business-класс
business_nodes = [n for n in all_nodes if calculate_score(n) >= 150]
finalize_and_save("business.txt", business_nodes)
finalize_and_save("business_lite.txt", business_nodes, limit=200)

# Твои фильтры Cable/Mobile
finalize_and_save("whitelist_cable.txt", [n for n in all_nodes if 'cable' in n.lower()], tag="CABLE-")
finalize_and_save("whitelist_mobile.txt", [n for n in all_nodes if 'mobile' in n.lower()], tag="MOB-")

if reader: reader.close()
log(f"🚀 ВСЁ ГОТОВО. Уникальных: {len(all_nodes)}")
]
for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

# --- ИНИЦИАЛИЗАЦИЯ GEOIP ---
GEOIP_DB_PATH = 'GeoLite2-Country.mmdb' # Файл должен лежать в папке со скриптом
reader = None
if os.path.exists(GEOIP_DB_PATH):
    reader = geoip2.database.Reader(GEOIP_DB_PATH)
else:
    print(f"⚠️ Файл {GEOIP_DB_PATH} не найден! Будет использован упрощенный поиск.")

geo_cache = {}

def get_country_code(node):
    try:
        # Извлекаем хост
        parsed = urlparse(node)
        host = parsed.netloc.split('@')[-1].split(':')[0]
        
        if host in geo_cache:
            return geo_cache[host]

        # Если это домен, резолвим в IP (быстро)
        ip = host
        if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            ip = socket.gethostbyname(host)

        if reader:
            response = reader.country(ip)
            code = response.country.iso_code
            geo_cache[host] = code
            return code
    except:
        pass
    
    # Резерв
    return "RU" if ".ru" in node.lower() else "UN"

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---

def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def get_flag(code):
    if not code or code == "UN" or code == "??": return "🌐"
    return "".join(chr(ord(c.upper()) + 127397) for c in code)

def calculate_score(config):
    score = 0
    c_l = config.lower()
    if 'xtls-rprx-vision' in c_l: score += 120
    if 'reality' in c_l: score += 80
    if 'pbk=' in c_l: score += 60
    sni_match = re.search(r'(?:sni|peer)=([^&?#]+)', c_l)
    if sni_match:
        found_sni = sni_match.group(1)
        if any(tsni in found_sni for tsni in TARGET_SNI):
            score += 100
    elif any(tsni in c_l for tsni in TARGET_SNI):
        score += 40
    return score

# --- ОСНОВНОЙ ЦИКЛ СБОРА ---

all_nodes = []
unique_map = {}

log(f"Начинаю сбор из {len(urls)} источников...")

for url in urls:
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200: continue
            
        content = r.text
        if "://" not in content[:100] and len(content) > 20:
            try:
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass

        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if "://" in line and not line.startswith("//"):
                key = line.split('#')[0]
                if key not in unique_map:
                    unique_map[key] = line
                    all_nodes.append(line)
    except: pass

log("Сортировка базы по качеству...")
all_nodes.sort(key=calculate_score, reverse=True)

# --- ГЕНЕРАЦИЯ ФАЙЛОВ ---

def finalize_and_save(filename, data, tag="", limit=None):
    if limit: data = data[:limit]
    output = []
    
    for i, node in enumerate(data):
        node_id = f"{i+1:05}"
        country = get_country_code(node)
        flag = get_flag(country)
        
        base_link = node.split('#')[0]
        new_name = f"{flag} {tag}{country}-{node_id}-HPP"
        output.append(f"{base_link}#{new_name}")
    
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(output))
    log(f"💾 {filename} готов.")

# Запись
finalize_and_save("sub.txt", all_nodes, limit=10000)
finalize_and_save("sub_lite.txt", all_nodes, limit=1000)
finalize_and_save("shadowsocks.txt", [n for n in all_nodes if n.startswith("ss://")], limit=2000)
finalize_and_save("vless_vmess.txt", [n for n in all_nodes if not n.startswith("ss://")], limit=5000)

business_nodes = [n for n in all_nodes if calculate_score(n) >= 150]
finalize_and_save("business.txt", business_nodes)

if reader: reader.close()
log(f"🚀 Готово. Уникальных: {len(all_nodes)}")

