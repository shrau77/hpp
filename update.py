import requests
import base64
import re
import random
from datetime import datetime

# Все твои ссылки, включая новую из VK Cloud
urls = [
    "https://etoneya.a9fm.site/",
    "https://etoneya.a9fm.site/2",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/LowiKLive/BypassWhitelistRu/refs/heads/main/WhiteList-Bypass_Ru.txt",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love"
]

def clean_name(config_line):
    if "#" not in config_line: return config_line
    base_part, name = config_line.split("#", 1)
    
    # Чистка рекламы и мусора
    name = re.sub(r'(?:https?://)?(?:t\.me|tg://[\w/?=]+)/[\w\d_]+', '', name)
    name = re.sub(r'@[\w\d_]+', '', name)
    trash = [r'подпишись', r'канал', r'project', r'обновлено', r'update', r'fresh', r'free', r'LowiKLive', r'Bypass', r'WhiteList', r'EtoNeYa']
    for pattern in trash:
        name = re.sub(pattern, '', name, flags=re.IGNORECASE)
    
    name = re.sub(r'[^\w\s\.]', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return f"{base_part}#{name if name else 'Server'}"

def save_encoded(configs, filename, label=""):
    # Добавляем инфо-строку с датой
    now = datetime.now().strftime("%d.%m %H:%M")
    info_line = f"vless://info#--- {label} ОБНОВЛЕНО: {now} ---"
    
    final_list = [info_line] + configs
    final_text = "\n".join(final_list)
    encoded = base64.b64encode(final_text.encode('utf-8')).decode('utf-8')
    with open(filename, "w", encoding="utf-8") as f:
        f.write(encoded)

def main():
    unique_configs = set()
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                if "://" not in content[:50]:
                    try: content = base64.b64decode(content).decode('utf-8')
                    except: pass
                for line in content.splitlines():
                    if "://" in line.strip():
                        unique_configs.add(clean_name(line.strip()))
        except: continue

    all_configs = list(unique_configs)
    
    # Распределение
    ss_only = sorted([c for c in all_configs if c.startswith("ss://")])
    v_only = sorted([c for c in all_configs if c.startswith("vless://") or c.startswith("vmess://") or c.startswith("trojan://")])

    # Сохраняем 4 разных файла
    save_encoded(sorted(all_configs), "sub.txt", "FULL")
    save_encoded(ss_only, "shadowsocks.txt", "WI-FI ONLY")
    save_encoded(v_only, "vless_vmess.txt", "MOBILE ONLY")
    
    # Бизнес-версия (смесь, 200 случайных)
    biz = random.sample(all_configs, min(len(all_configs), 200))
    save_encoded(sorted(biz), "business.txt", "VIP")

if __name__ == "__main__":
    main()
