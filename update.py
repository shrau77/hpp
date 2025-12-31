import requests
import base64
import re
import random

# --- КОНФИГУРАЦИЯ ---
# Твой расширенный список источников
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

# Добавляем 26 ссылок Goida (автогенерация)
for i in range(1, 27):
    urls.append(f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt")

# Ключевые слова для приоритизации (те самые Whitelist и Reality)
VIP_KEYWORDS = ['whitelist', 'reality', 'cable', 'mobile', 'ozon', 'vk', 'yandex']

def clean_name(config, index):
    """Очистка имени и добавление префикса HPP"""
    try:
        if '#' in config:
            base, name = config.split('#', 1)
            # Убираем мусор, оставляем только ГЕО (страну) если она есть
            geo_match = re.search(r'([A-Z]{2})', name.upper())
            geo = f" [{geo_match.group(1)}]" if geo_match else ""
            
            # Пометка протокола
            proto = "VLESS" if base.startswith("vless") else "SS" if base.startswith("ss") else "VPN"
            
            new_name = f"[HPP-{index:03d}]{geo} {proto} Premium"
            return f"{base}#{new_name}"
    except:
        pass
    return config

def get_weight(config):
    """Определяем 'крутость' конфига для сортировки"""
    weight = 0
    c_lower = config.lower()
    if 'reality' in c_lower: weight += 50
    if any(k in c_lower for k in VIP_KEYWORDS): weight += 30
    if 'vless' in c_lower: weight += 10
    return weight

# --- ОСНОВНОЙ ПРОЦЕСС ---
all_configs = []
unique_keys = set()

print(f"Начинаю сбор из {len(urls)} источников...")

for url in urls:
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            content = resp.text
            # Проверка на Base64
            if "://" not in content[:50]:
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except:
                    pass
            
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if "://" in line:
                    # Уникальность по IP и Порту (до знака #)
                    key = line.split('#')[0]
                    if key not in unique_keys:
                        unique_keys.add(key)
                        all_configs.append(line)
    except:
        continue

# Сортировка: самые "живучие" в начало
all_configs.sort(key=get_weight, reverse=True)

# Очистка имен (косметика)
final_configs = [clean_name(conf, i+1) for i, conf in enumerate(all_configs)]

# --- СОХРАНЕНИЕ ФАЙЛОВ ---
def save_file(name, data):
    with open(name, "w", encoding="utf-8") as f:
        f.write("\n".join(data))

# 1. sub.txt (Все)
save_file("sub.txt", final_configs)

# 2. sub_lite.txt (500 рандомных)
save_file("sub_lite.txt", random.sample(final_configs, min(500, len(final_configs))))

# 3. business.txt (Топ 1000 по качеству)
save_file("business.txt", final_configs[:1000])

# 4. business_lite.txt (200 рандомных из топ-500)
save_file("business_lite.txt", random.sample(final_configs[:500], min(200, len(final_configs[:500]))))

# 5. shadowsocks.txt
ss_only = [c for c in final_configs if c.startswith("ss://")]
save_file("shadowsocks.txt", ss_only)

# 6. vless_vmess.txt
modern_only = [c for c in final_configs if not c.startswith("ss://")]
save_file("vless_vmess.txt", modern_only)

print(f"Готово! Собрано уникальных конфигов: {len(final_configs)}")
 
