import requests
import base64
import re
import random

# --- КОНФИГУРАЦИЯ ИСТОЧНИКОВ ---
urls = [
    "https://etoneya.a9fm.site/",
    "https://etoneya.a9fm.site/2",
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

# Добавляем массив Goida (26 файлов)
for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

VIP_KEYWORDS = ['whitelist', 'reality', 'cable', 'mobile', 'ozon', 'vk', 'yandex']

def clean_name(config, index, tag=""):
    try:
        if '#' in config:
            base, _ = config.split('#', 1)
            proto = "VLESS" if base.startswith("vless") else "SS" if base.startswith("ss") else "VPN"
            prefix = f"[HPP-{tag}{index:03d}]" if tag else f"[HPP-{index:03d}]"
            return f"{base}#{prefix} {proto} Premium"
    except: pass
    return config

def get_weight(config):
    weight = 0
    c_lower = config.lower()
    if 'reality' in c_lower: weight += 50
    if any(k in c_lower for k in VIP_KEYWORDS): weight += 30
    return weight

# --- СБОР И ФИЛЬТРАЦИЯ ---
all_configs = []
unique_keys = set()

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
                if "://" in line:
                    key = line.split('#')[0]
                    if key not in unique_keys:
                        unique_keys.add(key)
                        all_configs.append(line)
    except: continue

# Сортировка по качеству (вес)
all_configs.sort(key=get_weight, reverse=True)
total_count = len(all_configs)

# --- СОХРАНЕНИЕ ---
def save_file(name, data, tag="", limit=None):
    if limit: data = data[:limit]
    with open(name, "w", encoding="utf-8") as f:
        f.write(f"// Total unique configs found: {total_count}\n")
        processed = [clean_name(conf, i+1, tag) for i, conf in enumerate(data)]
        f.write("\n".join(processed))

# 1. Основные файлы
save_file("sub.txt", all_configs, limit=10000)
save_file("sub_lite.txt", all_configs, limit=500)
save_file("business.txt", all_configs, limit=1000)
save_file("business_lite.txt", all_configs, limit=200)

# 2. По типам подключения (БС)
save_file("whitelist_cable.txt", [c for c in all_configs if 'cable' in c.lower()], tag="CABLE-")
save_file("whitelist_mobile.txt", [c for c in all_configs if 'mobile' in c.lower()], tag="MOB-")

# 3. По протоколам
save_file("shadowsocks.txt", [c for c in all_configs if c.startswith("ss://")], limit=2000)
save_file("vless_vmess.txt", [c for c in all_configs if not c.startswith("ss://")], limit=5000)

print(f"Готово! Обработано {total_count} конфигов.")
