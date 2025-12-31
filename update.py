import requests
import base64
import re

# --- КОНФИГУРАЦИЯ ---
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

for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

VIP_KEYWORDS = ['whitelist', 'reality', 'cable', 'mobile', 'ozon', 'vk', 'yandex']

def clean_name(config, index):
    try:
        if '#' in config:
            base, name = config.split('#', 1)
            geo_match = re.search(r'([A-Z]{2})', name.upper())
            geo = f" [{geo_match.group(1)}]" if geo_match else ""
            proto = "VLESS" if base.startswith("vless") else "SS" if base.startswith("ss") else "VPN"
            return f"{base}#[HPP-{index:03d}]{geo} {proto} Premium"
    except: pass
    return config

def get_weight(config):
    weight = 0
    c_lower = config.lower()
    if 'reality' in c_lower: weight += 50
    if any(k in c_lower for k in VIP_KEYWORDS): weight += 30
    if 'vless' in c_lower: weight += 10
    return weight

# --- СБОР ---
all_configs = []
unique_keys = set()

for url in urls:
    try:
        resp = requests.get(url, timeout=10)
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

all_configs.sort(key=get_weight, reverse=True)
total_count = len(all_configs)
final_configs = [clean_name(conf, i+1) for i, conf in enumerate(all_configs)]

# --- СОХРАНЕНИЕ ---
def save_file(name, data):
    with open(name, "w", encoding="utf-8") as f:
        # Добавляем инфо-комментарий в начало файла
        f.write(f"// Total unique configs collected: {total_count}\n")
        f.write("\n".join(data))

save_file("sub.txt", final_configs)
save_file("sub_lite.txt", final_configs[:500]) # Топ-500 для лайт версии
save_file("business.txt", final_configs[:1000]) # Топ-1000
save_file("business_lite.txt", final_configs[:200]) # Самые надежные ТОП-200
save_file("shadowsocks.txt", [c for c in final_configs if c.startswith("ss://")])
save_file("vless_vmess.txt", [c for c in final_configs if not c.startswith("ss://")])

print(f"Готово! Всего: {total_count}")
