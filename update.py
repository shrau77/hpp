import requests
import base64

# Твои источники
urls = [
    "https://etoneya.a9fm.site/",
    "https://etoneya.a9fm.site/2",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/1",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/2",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt"
]

def main():
    unique_configs = set()
    
    for url in urls:
        try:
            # Таймаут 10 сек, чтобы скрипт не вис на мертвых ссылках
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                content = resp.text
                # Если контент в base64 (часто бывает), пробуем декодировать
                if "://" not in content[:20]:
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                    except:
                        pass
                
                # Собираем все строки, похожие на конфиги
                for line in content.splitlines():
                    line = line.strip()
                    if "://" in line:
                        unique_configs.add(line)
        except Exception as e:
            print(f"Ошибка на {url}: {e}")

    # Сохраняем результат
    with open("sub.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(unique_configs))))

if __name__ == "__main__":
    main()
