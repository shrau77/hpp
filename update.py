import requests
import base64
import re
import random
from datetime import datetime

# Твои источники
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
    
    # Чистка мусора
    name = re.sub(r'(?:https?://)?(?:t\.me|tg://[\w/?=]+)/[\w\d_]+', '', name)
    name = re.sub(r'@[\w\d_]+', '', name)
    trash = [r'подпишись', r'канал', r'project', r'обновлено', r'update', r'fresh', r'free', r'LowiKLive', r'Bypass', r'WhiteList', r'EtoNeYa']
    for pattern in trash:
        name = re.sub(pattern, '', name, flags=re.IGNORECASE)
    
    name = re.sub(r'[^\w\s\.]', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return f"{base_part}#{name if name else 'Server'}"

def save_as_text(configs, filename, label=""):
    # Подбираем протокол для первой инфо-строки
    proto = "ss" if "shadowsocks" in filename else "vless"
    now = datetime.now().strftime("%d.%m %H:%M")
    
    # Красивая инфо-строка
    info_line = f"{proto}://info#--- {label} | {now} | СЕРВЕРОВ: {len(configs)} ---"
    
    final_text = "\n".join([info_line] + configs)
    
    # Сохраняем в чистом текстовом виде
    with open(filename, "w", encoding="utf-8") as f:
        f.write(final_text)

def main():
    unique_configs = set()
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                # Декодируем, если источник в base64
                if "://" not in content[:50]:
                    try: content = base64.b64decode(content).decode('utf-8')
                    except: pass
                
                for line in content.splitlines():
                    line = line.strip()
                    if "://" in line:
                        unique_configs.add(clean_name(line))
        except: continue

    all_configs = sorted(list(unique_configs))
    
    # Делим на группы
    ss_only = [c for c in all_configs if c.startswith("ss://")]
    v_only = [c for c in all_configs if not c.startswith("ss://")]

    # Сохраняем (БЕЗ Base64)
    save_as_text(all_configs, "sub.txt", "FULL-LIST")
    save_as_text(ss_only, "shadowsocks.txt", "WI-FI-ONLY")
    save_as_text(v_only, "vless_vmess.txt", "MOBILE-ONLY")
    
    # Бизнес-версия (200 штук)
    biz = random.sample(all_configs, min(len(all_configs), 200))
    save_as_text(sorted(biz), "business.txt", "VIP-ACCESS")

if __name__ == "__main__":
    main()
