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
    # Чистка мусора из названия
    name = re.sub(r'(?:https?://)?(?:t\.me|tg://[\w/?=]+)/[\w\d_]+', '', name)
    name = re.sub(r'@[\w\d_]+', '', name)
    trash = [r'подпишись', r'канал', r'project', r'обновлено', r'update', r'fresh', r'free', r'LowiKLive', r'Bypass', r'WhiteList', r'EtoNeYa']
    for pattern in trash:
        name = re.sub(pattern, '', name, flags=re.IGNORECASE)
    name = re.sub(r'[^\w\s\.]', ' ', name)
    name = re.sub(r'\s+', ' ', name).strip()
    return f"{base_part}#{name if name else 'Server'}"

def save_as_text(configs, filename, label=""):
    proto = "ss" if "shadowsocks" in filename else "vless"
    now = datetime.now().strftime("%d.%m %H:%M")
    info_line = f"{proto}://info#--- {label} | {now} | СЕРВЕРОВ: {len(configs)} ---"
    final_text = "\n".join([info_line] + configs)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(final_text)

def main():
    unique_configs = set()
    # ЖЕСТКИЙ ФИЛЬТР: только эти протоколы попадут в список
    allowed_protocols = ("vless://", "ss://", "vmess://", "trojan://", "hysteria2://", "tuic://", "hy2://")
    
    for url in urls:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                content = resp.text
                # Если контент в base64, декодируем
                if "://" not in content[:50]:
                    try: content = base64.b64decode(content).decode('utf-8')
                    except: pass
                
                for line in content.splitlines():
                    line = line.strip()
                    # Проверяем, начинается ли строка с нужного протокола
                    if line.lower().startswith(allowed_protocols):
                        unique_configs.add(clean_name(line))
        except: continue

    all_configs = sorted(list(unique_configs))
    
    # Сортировка по категориям
    ss_only = [c for c in all_configs if c.startswith("ss://")]
    v_modern = [c for c in all_configs if not c.startswith("ss://")]

    # 1. Полные списки
    save_as_text(all_configs, "sub.txt", "FULL-BASE")
    save_as_text(ss_only, "shadowsocks.txt", "WI-FI-ONLY")
    save_as_text(v_modern, "vless_vmess.txt", "MOBILE-ONLY")

    # 2. SUB LITE (500 штук)
    sub_lite = random.sample(all_configs, min(len(all_configs), 500))
    save_as_text(sorted(sub_lite), "sub_lite.txt", "SUB-LITE")

    # 3. BUSINESS (1000 современных)
    biz = random.sample(v_modern, min(len(v_modern), 1000))
    save_as_text(sorted(biz), "business.txt", "VIP-BUSINESS")

    # 4. BUSINESS LITE (200 современных)
    biz_lite = random.sample(v_modern, min(len(v_modern), 200))
    save_as_text(sorted(biz_lite), "business_lite.txt", "VIP-LITE")

if __name__ == "__main__":
    main()
