import requests, base64, re, random
from datetime import datetime

urls = [
    "https://etoneya.a9fm.site/",
    "https://etoneya.a9fm.site/2",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/miladtahanian/multi-proxy-config-fetcher/refs/heads/main/configs/proxy_configs.txt"
]

ELITE_SNI = ['ozon.ru', 'ozone.ru', 'vk.com', 'userapi.com', 'yandex.net', 'yandex.ru', 'mail.ru', 'sberbank.ru', 'tbank.ru', 'tinkoff.ru', 'wildberries.ru', 'gosuslugi.ru', 'avito.ru', 'rutube.ru', 'kinopoisk.ru', '2gis.ru', 'mts.ru']

def get_unique_key(config):
    try:
        content = config.split("://")[1]
        addr_part = content.split("@")[1] if "@" in content else content
        main_part = addr_part.split("?")[0].split("/")[0]
        return main_part
    except: return None

def get_weight(config_line):
    score = 0
    c_lower = config_line.lower()
    if any(proto in c_lower for proto in ["reality", "vision", "grpc", "h2"]): score += 500
    if any(domain in c_lower for domain in ELITE_SNI): score += 300
    if any(loc in c_lower.upper() for loc in ['RU', 'NL', 'DE', 'FI', 'KZ']): score += 100
    return score

def clean_name(config_line, node_id):
    """Максимально безопасная очистка без риска обрезать конфиг"""
    if "#" not in config_line: 
        return f"{config_line}#[HPP-{node_id}] Premium Server"
        
    # Разделяем только по ПЕРВОЙ решетке
    parts = config_line.split("#", 1)
    base_config = parts[0]
    raw_name = parts[1]
    
    # 1. Определяем ГЕО (ищем в оригинальном названии)
    locations = ['RU', 'NL', 'DE', 'FI', 'KZ', 'PL', 'TR', 'UK', 'US', 'FR', 'AT']
    geo_tag = ""
    name_up = raw_name.upper()
    for loc in locations:
        if loc in name_up:
            geo_tag = f"[{loc}] "
            break

    # 2. Удаляем мусор, hex-коды смайликов и рекламу ТГ
    # Убираем последовательности типа F0 9F 92...
    clean = re.sub(r'[A-F0-9]{2}(?:\s[A-F0-9]{2})+', '', raw_name)
    # Убираем ссылки и @юзернеймы
    clean = re.sub(r'(?:https?://)?(?:t\.me|tg://[\w/?=]+)/[\w\d_]+|@[\w\d_]+', '', clean)
    # Убираем цифровые индексы в начале строки
    clean = re.sub(r'^\s*\d+[\s\.\-_]*', '', clean)
    # Оставляем только буквы, цифры и пробелы
    clean = re.sub(r'[^\w\s]', ' ', clean)
    
    # Черный список слов (если они есть, название заменяется)
    stop_words = ['join', 'telegram', 'channel', 'подпишись', 'канал', 'group', 'реклама']
    if any(word in clean.lower() for word in stop_words):
        clean = "Ultra Fast"

    # Доп. чистка технических слов
    for trash in ['VLESS', 'VMESS', 'TG', 'UPDATE', 'FRESH', 'FREE', 'BYPASS']:
        clean = re.sub(trash, '', clean, flags=re.IGNORECASE)
    
    clean = re.sub(r'\s+', ' ', clean).strip()
    
    if len(clean) < 2: clean = "Premium Server"

    # Формируем безопасное название
    final_label = f"[HPP-{node_id}] {geo_tag}{clean}"[:55]
    return f"{base_config}#{final_label}"

def save_as_text(configs, filename, label=""):
    now = datetime.now().strftime("%d.%m %H:%M")
    info = f"# --- {label} | {now} | NODES: {len(configs)} ---"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join([info] + configs))

def main():
    unique_keys = set()
    raw_configs = []
    allowed = ("vless://", "ss://", "vmess://", "trojan://", "hysteria2://", "tuic://", "hy2://")
    
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                if "://" not in content[:50]:
                    try: content = base64.b64decode(content).decode('utf-8')
                    except: pass
                for line in content.splitlines():
                    line = line.strip()
                    if line.lower().startswith(allowed):
                        key = get_unique_key(line)
                        if key and key not in unique_keys:
                            unique_keys.add(key)
                            raw_configs.append(line)
        except: continue

    weighted_all = sorted([(get_weight(c), c) for c in raw_configs], key=lambda x: x[0], reverse=True)
    sorted_all = [x[1] for x in weighted_all]
    v_modern = [c for c in sorted_all if not c.startswith("ss://")]

    def finalize_list(subset):
        return [clean_name(line, str(i + 1).zfill(3)) for i, line in enumerate(subset)]

    save_as_text(finalize_list(sorted_all), "sub.txt", "FULL-BASE")
    save_as_text(finalize_list(v_modern), "vless_vmess.txt", "MOBILE-ONLY")
    save_as_text(finalize_list(sorted_all[:1000]), "business.txt", "VIP-BUSINESS")
    
    top_500 = sorted_all[:500]
    save_as_text(finalize_list(random.sample(top_500, min(len(top_500), 200))), "business_lite.txt", "VIP-LITE")
    save_as_text(finalize_list(random.sample(sorted_all, min(len(sorted_all), 500))), "sub_lite.txt", "SUB-LITE")

if __name__ == "__main__":
    main()
