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

ELITE_SNI = [
    'ozon.ru', 'ozone.ru', 'vk.com', 'userapi.com', 'yandex.net', 'yandex.ru',
    'mail.ru', 'sberbank.ru', 'tbank.ru', 'tinkoff.ru', 'wildberries.ru',
    'gosuslugi.ru', 'avito.ru', 'rutube.ru', 'kinopoisk.ru', '2gis.ru', 'mts.ru'
]

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
    if any(proto in c_lower for proto in ["reality", "vision", "grpc", "h2"]):
        score += 500
    if any(domain in c_lower for domain in ELITE_SNI):
        score += 300
    if any(loc in c_lower.upper() for loc in ['RU', 'NL', 'DE', 'FI', 'KZ']):
        score += 100
    return score

def clean_name(config_line, node_id):
    """Исправлено: теперь не режет тело конфига"""
    if "#" not in config_line: 
        return f"{config_line}#[HPP-{node_id}] Premium Server"
        
    # Разделяем СТРОГО на две части: конфиг (base) и имя (old_name)
    parts = config_line.split("#", 1)
    base = parts[0]
    old_name = parts[1]
    
    # 1. Вычисляем ГЕО
    locations = ['RU', 'NL', 'DE', 'FI', 'KZ', 'PL', 'TR', 'UK', 'US', 'FR', 'AT']
    found_loc = ""
    name_upper = old_name.upper()
    for loc in locations:
        if loc in name_upper:
            found_loc = f"[{loc}] "
            break

    # 2. Чистим текст после решетки от мусора
    temp_name = re.sub(r'(?:https?://)?(?:t\.me|tg://[\w/?=]+)/[\w\d_]+|@[\w\d_]+', '', old_name)
    temp_name = re.sub(r'[^\w\s]', ' ', temp_name)
    trash = ['подпишись', 'канал', 'project', 'обновлено', 'update', 'fresh', 'free', 'LowiKLive', 'Bypass', 'WhiteList', 'EtoNeYa']
    for p in trash: 
        temp_name = re.sub(p, '', temp_name, flags=re.IGNORECASE)
    
    temp_name = re.sub(r'\s+', ' ', temp_name).strip()
    
    if not temp_name or len(temp_name) < 2: 
        temp_name = "Premium Node"

    # 3. Собираем финальное имя (обрезаем ТОЛЬКО название до 50 символов)
    clean_label = f"[HPP-{node_id}] {found_loc}{temp_name}"[:50]
    
    # Склеиваем обратно ЦЕЛЫЙ base и новое имя
    return f"{base}#{clean_label}"

def save_as_text(configs, filename, label=""):
    now = datetime.now().strftime("%d.%m %H:%M")
    info_comment = f"# --- {label} | {now} | NODES: {len(configs)} ---"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join([info_comment] + configs))

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

    # Сортировка по весу (лучшие вверх)
    weighted_all = sorted([(get_weight(c), c) for c in raw_configs], key=lambda x: x[0], reverse=True)
    sorted_all = [x[1] for x in weighted_all]

    v_modern = [c for c in sorted_all if not c.startswith("ss://")]
    ss_only = [c for c in sorted_all if c.startswith("ss://")]

    def finalize_list(subset):
        return [clean_name(line, str(i + 1).zfill(3)) for i, line in enumerate(subset)]

    save_as_text(finalize_list(sorted_all), "sub.txt", "FULL-BASE")
    save_as_text(finalize_list(ss_only), "shadowsocks.txt", "WI-FI-ONLY")
    save_as_text(finalize_list(v_modern), "vless_vmess.txt", "MOBILE-ONLY")
    
    top_500 = sorted_all[:500]
    save_as_text(finalize_list(random.sample(top_500, min(len(top_500), 200))), "business_lite.txt", "VIP-LITE")
    save_as_text(finalize_list(sorted_all[:1000]), "business.txt", "VIP-BUSINESS")
    save_as_text(finalize_list(random.sample(sorted_all, min(len(sorted_all), 500))), "sub_lite.txt", "SUB-LITE")

if __name__ == "__main__":
    main()
