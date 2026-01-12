import asyncio
import aiohttp
import base64
import re
import os
import json
import hashlib
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from typing import List, Dict, Set, Optional, Tuple
import socket

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

# ASN Blacklist - забаненные хостинги
ASN_BLACKLIST = {
    'hetzner', 'digitalocean', 'ovh', 'linode', 'vultr', 
    'contabo', 'amazon', 'google', 'microsoft', 'cloudflare'
}

# Разрешенные протоколы
ALLOWED_PROTOCOLS = {'vless', 'hysteria2', 'hy2', 'tuic', 'ss'}

# Современные методы Shadowsocks
MODERN_SS_METHODS = {
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm', 
    '2022-blake3-chacha20-poly1305',
    'aes-256-gcm',
    'chacha20-ietf-poly1305'
}

# User-Agent для ротации
USER_AGENTS = [
    'Happ/3.7.0',
    'Happ/3.8.1'
]

# Элитные SNI (сохраняем из оригинала)
ULTRA_ELITE_SNI = [
    "hls-svod.itunes.apple.com", "itunes.apple.com",
    "fastsync.xyz", "cloudlane.xyz", "powodzenia.xyz", 
    "shiftline.xyz", "edgeport.xyz",
    "stats.vk-portal.net", "akashi.vk-portal.net",
    "deepl.com", "www.samsung.com", "cdnjs.cloudflare.com",
    "st.ozone.ru", "disk.yandex.ru", "api.mindbox.ru",
    "travel.yandex.ru", "egress.yandex.net", "sba.yandex.net",
    "strm.yandex.net", "goya.rutube.ru",
]

# Целевые SNI для российских пользователей
TARGET_SNI = [
    "www.unicreditbank.ru", "www.gazprombank.ru", "cdn.gpb.ru", "mkb.ru", "www.open.ru",
    "cobrowsing.tbank.ru", "cdn.rosbank.ru", "www.psbank.ru", "www.raiffeisen.ru",
    "www.rzd.ru", "st.gismeteo.st", "stat-api.gismeteo.net", "c.dns-shop.ru",
    "restapi.dns-shop.ru", "www.pochta.ru", "passport.pochta.ru", "chat-ct.pochta.ru",
    "www.x5.ru", "www.ivi.ru", "api2.ivi.ru", "hh.ru", "i.hh.ru", "hhcdn.ru",
    "sentry.hh.ru", "cpa.hh.ru", "www.kp.ru", "cdnn21.img.ria.ru", "lenta.ru",
    "sync.rambler.ru", "s.rbk.ru", "www.rbc.ru", "target.smi2.net", "hb-bidder.skcrtxr.com",
    "strm-spbmiran-07.strm.yandex.net", "pikabu.ru", "www.tutu.ru", "cdn1.tu-tu.ru",
    "api.apteka.ru", "static.apteka.ru", "images.apteka.ru", "scitylana.apteka.ru",
    "www.drom.ru", "c.rdrom.ru", "www.farpost.ru", "s11.auto.drom.ru", "i.rdrom.ru",
    "yummy.drom.ru", "www.drive2.ru", "lemanapro.ru", "stats.vk-portal.net",
    "sun6-21.userapi.com", "sun6-20.userapi.com", "avatars.mds.yandex.net",
    "queuev4.vk.com", "sun6-22.userapi.com", "sync.browser.yandex.net", "top-fwz1.mail.ru",
    "ad.mail.ru", "eh.vk.com", "akashi.vk-portal.net", "sun9-38.userapi.com",
    "st.ozone.ru", "ir.ozone.ru", "vt-1.ozone.ru", "io.ozone.ru", "ozone.ru",
    "xapi.ozon.ru", "strm-rad-23.strm.yandex.net", "online.sberbank.ru",
    "esa-res.online.sberbank.ru", "egress.yandex.net", "st.okcdn.ru", "rs.mail.ru",
    "counter.yadro.ru", "742231.ms.ok.ru", "splitter.wb.ru", "a.wb.ru",
    "user-geo-data.wildberries.ru", "banners-website.wildberries.ru",
    "chat-prod.wildberries.ru", "servicepipe.ru", "alfabank.ru", "statad.ru",
    "alfabank.servicecdn.ru", "alfabank.st", "ad.adriver.ru", "privacy-cs.mail.ru",
    "imgproxy.cdn-tinkoff.ru", "mddc.tinkoff.ru", "le.tbank.ru", "hrc.tbank.ru",
    "id.tbank.ru", "rap.skcrtxr.com", "eye.targetads.io", "px.adhigh.net", "nspk.ru",
    "sba.yandex.net", "identitystatic.mts.ru", "tag.a.mts.ru", "login.mts.ru",
    "serving.a.mts.ru", "cm.a.mts.ru", "login.vk.com", "api.a.mts.ru", "mtscdn.ru",
    "d5de4k0ri8jba7ucdbt6.apigw.yandexcloud.net", "moscow.megafon.ru", "api.mindbox.ru",
    "web-static.mindbox.ru", "storage.yandexcloud.net", "personalization-web-stable.mindbox.ru",
    "www.t2.ru", "beeline.api.flocktory.com", "static.beeline.ru", "moskva.beeline.ru",
    "wcm.weborama-tech.ru", "1013a--ma--8935--cp199.stbid.ru", "msk.t2.ru", "s3.t2.ru",
    "get4click.ru", "dzen.ru", "yastatic.net", "csp.yandex.net", "sntr.avito.ru",
    "yabro-wbplugin.edadeal.yandex.ru", "cdn.uxfeedback.ru", "goya.rutube.ru",
    "api.expf.ru", "fb-cdn.premier.one", "www.kinopoisk.ru", "widgets.kinopoisk.ru",
    "payment-widget.plus.kinopoisk.ru", "api.events.plus.yandex.net", "tns-counter.ru",
    "speller.yandex.net", "widgets.cbonds.ru", "www.magnit.com", "magnit-ru.injector.3ebra.net",
    "jsons.injector.3ebra.net", "2gis.ru", "d-assets.2gis.ru", "s1.bss.2gis.com",
    "www.tbank.ru", "strm-spbmiran-08.strm.yandex.net", "id.tbank.ru", "tmsg.tbank.ru",
    "vk.com", "www.wildberries.ru", "www.ozon.ru", "ok.ru", "yandex.ru"
]

# Черный список SNI
BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'porn']

# Элитные порты
ELITE_PORTS = {'2053', '2083', '2087', '2096', '8447', '9443', '10443', '443'}

# Таймауты
TCP_CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 15

# Лимиты
MAX_NODES_TO_CHECK = 5000
MAX_CONCURRENT_CHECKS = 200

# Источники конфигураций
SOURCES = [
    "https://s3c3.001.gpucloud.ru/dggdu/xixz",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/config.txt", 
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/STR97/STRUGOV/refs/heads/main/STR.BYPASS", 
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    "https://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt",
    "https://etoneya.a9fm.site/1",
    "https://bp.wl.free.nf/confs/merged.txt", 
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no1.txt", 
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no2.txt", 
    "https://bp.wl.free.nf/confs/wl.txt",
    "https://bp.wl.free.nf/confs/selected.txt",
    "https://bp.wl.free.nf/confs/merged.txt",
    "https://raw.githubusercontent.com/FLEXIY0/matryoshka-vpn/main/configs/russia_whitelist.txt" 
    "https://storage.yandexcloud.net/nllrcn-proxy-subs/subs/main-sub.txt", 
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/main-sub.txt", 
    "https://storage.yandexcloud.net/cid-vpn/whitelist.txt", 
    "http://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt", 
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh#OBSpiskov",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt", 
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt", 
    "https://fsub.flux.2bd.net/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/vmess.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/trojan.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/tuic.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/ssr.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria2.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hy2.txt",
    "http://livpn.atwebpages.com/sub.php?token=c829c20769d2112b", 
    "https://sub-aggregator.vercel.app/",
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no1.txt", 
    "https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/refs/heads/main/v2ray_configs_no2.txt", 
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/split-by-protocols/vless-secure.txt", 
    "https://s3c3.001.gpucloud.ru/dixsm/htxml",
    "https://shz.al/YjSPQaSTpHYNakFnE2ddjcCK:/~@sorenab1,/VIESS,subSOREN#VIESS,subSOREN", 
    "https://s3c3.001.gpucloud.ru/rtrq/jsoxn", 
    "https://raw.githubusercontent.com/bywarm/whitelists-vpns-etc/refs/heads/main/whitelists1-4pda.txt", 
    *[f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt" for i in range(1, 27)]
]

# Добавляем источники из диапазона
SOURCES.extend([
    f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt" 
    for i in range(1, 27)
])

# ============================================================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def get_node_hash(node: str) -> str:
    """Генерирует хеш для ноды (без тега)"""
    base_link = node.split('#')[0]
    return hashlib.md5(base_link.encode()).hexdigest()

def extract_protocol(node: str) -> Optional[str]:
    """Извлекает протокол из ноды"""
    if node.startswith('ss://'):
        return 'ss'
    elif node.startswith('vless://'):
        return 'vless'
    elif node.startswith('trojan://'):
        return 'trojan'
    elif 'hysteria2' in node.lower() or 'hy2' in node.lower():
        return 'hysteria2'
    elif 'tuic' in node.lower():
        return 'tuic'
    return None

def extract_sni(node: str) -> Optional[str]:
    """Извлекает SNI из ноды"""
    try:
        match = re.search(r'[?&]sni=([^&?#\s]+)', node.lower())
        if match:
            return match.group(1).strip('.')
    except:
        pass
    return None

def extract_host_port(node: str) -> Optional[Tuple[str, int]]:
    """Извлекает хост и порт из ноды"""
    try:
        parsed = urlparse(node)
        netloc = parsed.netloc.split('@')[-1]  # Убираем user info
        
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            return (host, int(port))
        else:
            return (netloc, 443)  # Дефолтный порт
    except:
        return None

def is_blacklisted_host(host: str) -> bool:
    """Проверяет, находится ли хост в черном списке ASN"""
    host_lower = host.lower()
    return any(asn in host_lower for asn in ASN_BLACKLIST)

def validate_ss_method(node: str) -> bool:
    """Проверяет, использует ли Shadowsocks современный метод"""
    try:
        # Попытка извлечь метод из base64
        base_part = node[5:].split('#')[0].split('@')[0]
        
        try:
            decoded = base64.b64decode(base_part + '=' * (4 - len(base_part) % 4)).decode('utf-8', errors='ignore')
            method = decoded.split(':')[0]
            return method in MODERN_SS_METHODS
        except:
            # Если не получилось декодировать, проверяем по строке
            return any(method in node.lower() for method in MODERN_SS_METHODS)
    except:
        return False

def is_ip_address(host: str) -> bool:
    """Проверяет, является ли строка IP-адресом"""
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))

# ============================================================================
# КЛАСС REPUTATION MANAGER
# ============================================================================

class ReputationManager:
    """Управление репутацией серверов"""
    
    def __init__(self, reputation_file: str = 'reputation.json'):
        self.reputation_file = reputation_file
        self.reputation: Dict[str, Dict] = self._load()
        
    def _load(self) -> Dict:
        """Загружает репутацию из файла"""
        if os.path.exists(self.reputation_file):
            try:
                with open(self.reputation_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Миграция старого формата
                    for k, v in data.items():
                        if isinstance(v, int):
                            data[k] = {"count": v, "last_seen": int(time.time())}
                    return data
            except:
                return {}
        return {}
    
    def save(self):
        """Сохраняет репутацию в файл"""
        try:
            with open(self.reputation_file, 'w', encoding='utf-8') as f:
                json.dump(self.reputation, f, indent=2)
        except Exception as e:
            print(f"❌ Ошибка сохранения репутации: {e}")
    
    def update(self, node_hash: str):
        """Обновляет репутацию ноды"""
        now = int(time.time())
        if node_hash not in self.reputation:
            self.reputation[node_hash] = {"count": 0, "last_seen": now}
        
        self.reputation[node_hash]["count"] += 1
        self.reputation[node_hash]["last_seen"] = now
    
    def get_count(self, node_hash: str) -> int:
        """Возвращает счетчик репутации"""
        return self.reputation.get(node_hash, {}).get("count", 0)
    
    def cleanup(self, max_age_days: int = 30, max_entries: int = 10000):
        """Очищает старые записи репутации"""
        now = int(time.time())
        cutoff = now - (max_age_days * 86400)
        
        # Удаляем старые записи
        clean_db = {
            k: v for k, v in self.reputation.items() 
            if v.get('last_seen', 0) > cutoff
        }
        
        # Ограничиваем размер
        if len(clean_db) > max_entries:
            sorted_rep = sorted(
                clean_db.items(), 
                key=lambda x: x[1]['count'], 
                reverse=True
            )
            clean_db = dict(sorted_rep[:max_entries])
        
        self.reputation = clean_db
    
    def clear(self):
        """Полная очистка репутации"""
        self.reputation = {}
        if os.path.exists(self.reputation_file):
            os.remove(self.reputation_file)
        print("✅ Репутация полностью очищена")
class NodeScorer:
    """Система оценки качества нод"""
    
    def __init__(self, reputation_manager: 'ReputationManager'):
        self.reputation = reputation_manager
        self.uuid_counter: Dict[str, int] = {}
        self.sni_counter: Dict[str, int] = {}
    
    def update_statistics(self, nodes: List[str]):
        """Обновляет статистику UUID и SNI"""
        self.uuid_counter.clear()
        self.sni_counter.clear()
        
        for node in nodes:
            try:
                uuid = self._extract_uuid(node)
                if uuid:
                    self.uuid_counter[uuid] = self.uuid_counter.get(uuid, 0) + 1
                
                sni = extract_sni(node)
                if sni:
                    self.sni_counter[sni] = self.sni_counter.get(sni, 0) + 1
            except:
                continue
    
    def _extract_uuid(self, node: str) -> Optional[str]:
        """Извлекает UUID из ноды"""
        try:
            if node.startswith('vmess://'):
                uuid_match = re.search(
                    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
                    node, 
                    re.IGNORECASE
                )
                if uuid_match:
                    return uuid_match.group(0)
            
            elif node.startswith(('vless://', 'trojan://')):
                parsed = urlparse(node)
                user_info = parsed.netloc.split('@')[0]
                if user_info and '@' in parsed.netloc:
                    return user_info
        except:
            pass
        return None
    
    def calculate_score(self, node: str) -> int:
        """Вычисляет оценку ноды"""
        score = 0
        n_l = node.lower()
        
        # Базовая репутация
        node_hash = get_node_hash(node)
        rep_count = self.reputation.get_count(node_hash)
        score += rep_count * 50
        
        # Протокол
        protocol = extract_protocol(node)
        
        # Hysteria2 - высший приоритет
        if protocol == 'hysteria2':
            score += 600
        
        # VLESS Reality/Vision
        if protocol == 'vless':
            if 'flow=xtls-rprx-vision' in n_l:
                score += 500
            elif 'reality' in n_l:
                score += 400
            else:
                score += 200
        
        # TUIC
        if protocol == 'tuic':
            score += 450
        
        # Trojan
        if protocol == 'trojan':
            if 'reality' in n_l:
                score += 350
            else:
                score += 150
        
        # Современные транспорты
        if 'type=grpc' in n_l:
            score += 100
        if 'type=ws' in n_l:
            score += 50
        
        # Порты
        host_port = extract_host_port(node)
        if host_port:
            _, port = host_port
            if str(port) in ELITE_PORTS:
                score += 250
            elif port == 443:
                score += 100
        
        # SNI анализ
        sni = extract_sni(node)
        if sni:
            # Черный список
            if any(black in sni for black in BLACK_SNI):
                score -= 2000
            
            # Элитные SNI
            if any(elite in sni for elite in ULTRA_ELITE_SNI):
                score += 300
            
            # Целевые SNI
            if any(target == sni or sni.endswith('.' + target) for target in TARGET_SNI):
                score += 200
            
            # Редкие SNI
            sni_freq = self.sni_counter.get(sni, 0)
            if sni_freq <= 5:
                score += 100
            
            # Поддомены
            if sni.count('.') >= 3 or any(sub in sni for sub in ['st.', 'api.', 'cdn.', 'disk.']):
                score += 80
        
        # UUID частота
        uuid = self._extract_uuid(node)
        if uuid:
            uuid_freq = self.uuid_counter.get(uuid, 0)
            if uuid_freq >= 10:
                score += 150
            elif uuid_freq >= 5:
                score += 80
            elif uuid_freq >= 2:
                score += 30
        
        # ALPN
        if 'alpn=h3' in n_l or 'alpn=h3-29' in n_l:
            score += 60
        elif 'alpn=h2' in n_l:
            score += 30
        
        # Fingerprint разнообразие
        if any(fp in n_l for fp in ['fp=safari', 'fp=ios', 'fp=firefox', 'fp=edge']):
            score += 50
        
        return max(score, 0)
    
    def get_tier(self, score: int, protocol: str) -> int:
        """Определяет тир ноды"""
        # Tier 1: Hysteria2/Reality с высоким скором
        if protocol in ['hysteria2', 'tuic']:
            if score >= 500:
                return 1
        
        if protocol == 'vless' and ('reality' in protocol or 'vision' in protocol):
            if score >= 400:
                return 1
        
        # Tier 2: остальные живые
        if score >= 150:
            return 2
        
        # Tier 3: низкое качество
        return 3

# ============================================================================
# ФИЛЬТРАЦИЯ И ВАЛИДАЦИЯ
# ============================================================================

class NodeFilter:
    """Фильтрация и валидация нод"""
    
    @staticmethod
    def is_valid_protocol(node: str) -> bool:
        """Проверяет, разрешен ли протокол"""
        protocol = extract_protocol(node)
        
        if protocol == 'ss':
            return validate_ss_method(node)
        
        return protocol in ALLOWED_PROTOCOLS
    
    @staticmethod
    def is_blacklisted(node: str) -> bool:
        """Проверяет черный список"""
        # Проверка мусорных адресов
        if any(trash in node for trash in ["0.0.0.0", "127.0.0.1", "localhost"]):
            return True
        
        # Проверка хоста
        host_port = extract_host_port(node)
        if host_port:
            host, _ = host_port
            if is_blacklisted_host(host):
                return True
        
        # Проверка SNI
        sni = extract_sni(node)
        if sni and any(black in sni for black in BLACK_SNI):
            return True
        
        return False
    
    @staticmethod
    def clean_node(node: str) -> str:
        """Очищает ноду, убирая только комментарий"""
        # Убираем только тег после #
        return node.split('#')[0]
    
    @staticmethod
    def deduplicate_key(node: str) -> str:
        """Генерирует ключ для дедупликации: protocol:ip:port"""
        try:
            protocol = extract_protocol(node)
            host_port = extract_host_port(node)
            
            if host_port:
                host, port = host_port
                return f"{protocol}:{host}:{port}"
        except:
            pass
        
        # Фоллбэк на хеш
        return get_node_hash(node)
    
    @staticmethod
    def parse_nodes_from_text(text: str) -> List[str]:
        """Парсит ноды из текста"""
        nodes = []
        
        # Попытка декодировать base64
        if "://" not in text[:100]:
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                text = decoded
            except:
                pass
        
        # Извлекаем строки с протоколами
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(('/', '#', ';')):
                continue
            
            # Проверяем наличие протокола
            if any(proto in line for proto in ['://', 'ss://', 'vless://', 'trojan://', 'hysteria2://', 'tuic://']):
                nodes.append(line)
        
        return nodes

# ============================================================================
# АСИНХРОННАЯ ПРОВЕРКА TCP
# ============================================================================

class AsyncTCPChecker:
    """Асинхронная проверка доступности TCP портов"""
    
    def __init__(self, timeout: float = TCP_CONNECT_TIMEOUT, max_concurrent: int = MAX_CONCURRENT_CHECKS):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results = {}
    
    async def check_port(self, host: str, port: int) -> bool:
        """Проверяет доступность порта"""
        async with self.semaphore:
            try:
                # Попытка подключения
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                
                # Закрываем соединение
                writer.close()
                await writer.wait_closed()
                
                return True
            
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return False
            except Exception as e:
                # Логируем неожиданные ошибки
                # print(f"Неожиданная ошибка при проверке {host}:{port}: {e}")
                return False
    
    async def check_node(self, node: str) -> Tuple[str, bool]:
        """Проверяет ноду"""
        host_port = extract_host_port(node)
        
        if not host_port:
            return (node, False)
        
        host, port = host_port
        
        # Кэш результатов
        cache_key = f"{host}:{port}"
        if cache_key in self.results:
            return (node, self.results[cache_key])
        
        # Проверка
        is_alive = await self.check_port(host, port)
        self.results[cache_key] = is_alive
        
        return (node, is_alive)
    
    async def check_batch(self, nodes: List[str]) -> List[str]:
        """Проверяет batch нод"""
        tasks = [self.check_node(node) for node in nodes]
        results = await asyncio.gather(*tasks)
        
        # Возвращаем только живые ноды
        alive_nodes = [node for node, is_alive in results if is_alive]
        
        return alive_nodes

# ============================================================================
# АСИНХРОННЫЙ ЗАГРУЗЧИК
# ============================================================================

class AsyncDownloader:
    """Асинхронная загрузка конфигураций"""
    
    def __init__(self, timeout: int = HTTP_TIMEOUT):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent_idx = 0
    
    def _get_user_agent(self) -> str:
        """Ротация User-Agent"""
        ua = USER_AGENTS[self.user_agent_idx]
        self.user_agent_idx = (self.user_agent_idx + 1) % len(USER_AGENTS)
        return ua
    
    async def fetch(self, session: aiohttp.ClientSession, url: str) -> str:
        """Загружает один источник"""
        try:
            headers = {'User-Agent': self._get_user_agent()}
            async with session.get(url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    print(f"⚠️ {url[:60]}... -> HTTP {response.status}")
                    return ""
        except asyncio.TimeoutError:
            print(f"⏱️ Таймаут: {url[:60]}...")
            return ""
        except Exception as e:
            print(f"❌ Ошибка: {url[:60]}... -> {str(e)[:50]}")
            return ""
    
    async def fetch_all(self, urls: List[str]) -> List[str]:
        """Загружает все источники"""
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch(session, url) for url in urls]
            results = await asyncio.gather(*tasks)
            return results
class ProxyAggregator:
    """Главный класс агрегатора"""
    
    def __init__(self):
        self.reputation = ReputationManager()
        self.scorer = NodeScorer(self.reputation)
        self.filter = NodeFilter()
        self.downloader = AsyncDownloader()
        self.checker = AsyncTCPChecker()
        
        self.raw_nodes: List[str] = []
        self.filtered_nodes: List[Dict] = []
        self.checked_nodes: List[Dict] = []
    
    async def download_sources(self):
        """Скачивает все источники"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📥 Загрузка источников...")
        
        results = await self.downloader.fetch_all(SOURCES)
        
        total_nodes = 0
        for idx, content in enumerate(results):
            if not content:
                continue
            
            nodes = self.filter.parse_nodes_from_text(content)
            self.raw_nodes.extend(nodes)
            total_nodes += len(nodes)
            
            if len(nodes) > 0:
                print(f"  ✓ Источник {idx+1}: {len(nodes)} нод")
        
        print(f"📊 Всего загружено: {total_nodes} нод")
    
    def filter_and_deduplicate(self):
        """Фильтрует и дедуплицирует ноды"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔍 Фильтрация и дедупликация...")
        
        # Словарь для дедупликации
        unique_map: Dict[str, Dict] = {}
        
        processed = 0
        filtered_out = {
            'blacklist': 0,
            'protocol': 0,
            'duplicate': 0
        }
        
        for node in self.raw_nodes:
            processed += 1
            
            if processed % 5000 == 0:
                print(f"  🔄 Обработано {processed}/{len(self.raw_nodes)}")
            
            # Очистка
            clean_node = self.filter.clean_node(node)
            
            # Проверка черного списка
            if self.filter.is_blacklisted(clean_node):
                filtered_out['blacklist'] += 1
                continue
            
            # Проверка протокола
            if not self.filter.is_valid_protocol(clean_node):
                filtered_out['protocol'] += 1
                continue
            
            # Дедупликация
            dedup_key = self.filter.deduplicate_key(clean_node)
            
            if dedup_key in unique_map:
                filtered_out['duplicate'] += 1
                continue
            
            # Сохраняем
            protocol = extract_protocol(clean_node)
            unique_map[dedup_key] = {
                'node': clean_node,
                'protocol': protocol,
                'original': node  # Сохраняем оригинал с тегом
            }
        
        # Конвертируем в список
        self.filtered_nodes = list(unique_map.values())
        
        print(f"✅ Уникальных нод: {len(self.filtered_nodes)}")
        print(f"  📛 Фильтры: blacklist={filtered_out['blacklist']}, "
              f"protocol={filtered_out['protocol']}, duplicate={filtered_out['duplicate']}")
    
    def calculate_scores(self):
        """Вычисляет оценки для нод"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 📊 Расчет оценок...")
        
        # Обновляем статистику
        nodes_list = [n['node'] for n in self.filtered_nodes]
        self.scorer.update_statistics(nodes_list)
        
        # Вычисляем оценки
        for node_data in self.filtered_nodes:
            node = node_data['node']
            score = self.scorer.calculate_score(node)
            tier = self.scorer.get_tier(score, node_data['protocol'])
            
            node_data['score'] = score
            node_data['tier'] = tier
        
        # Сортируем по оценке
        self.filtered_nodes.sort(key=lambda x: x['score'], reverse=True)
        
        print(f"✅ Оценки рассчитаны")
    
    async def check_nodes(self):
        """Проверяет доступность нод"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔌 Проверка доступности...")
        
        # Берем топ-5000 для проверки
        nodes_to_check = self.filtered_nodes[:MAX_NODES_TO_CHECK]
        nodes_list = [n['node'] for n in nodes_to_check]
        
        print(f"  📡 Проверка {len(nodes_list)} нод (timeout={TCP_CONNECT_TIMEOUT}s)...")
        
        # Асинхронная проверка
        alive_nodes = await self.checker.check_batch(nodes_list)
        alive_set = set(alive_nodes)
        
        # Фильтруем живые
        self.checked_nodes = [
            n for n in self.filtered_nodes 
            if n['node'] in alive_set or self.filtered_nodes.index(n) >= MAX_NODES_TO_CHECK
        ]
        
        alive_count = len(alive_nodes)
        dead_count = len(nodes_list) - alive_count
        
        print(f"✅ Живых: {alive_count} | ❌ Мертвых: {dead_count}")
        print(f"📊 Итого нод после проверки: {len(self.checked_nodes)}")
    
    def update_reputation(self):
        """Обновляет репутацию"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Обновление репутации...")
        
        for node_data in self.checked_nodes:
            node_hash = get_node_hash(node_data['node'])
            self.reputation.update(node_hash)
        
        # Очистка старых записей
        self.reputation.cleanup()
        
        # Сохранение
        self.reputation.save()
        
        print(f"✅ Репутация обновлена ({len(self.reputation.reputation)} записей)")
    
    def generate_server_name(self, node_data: Dict, index: int) -> str:
        """Генерирует имя сервера"""
        protocol = node_data['protocol'].upper()
        score = node_data['score']
        tier = node_data['tier']
        
        # Определяем качество
        if tier == 1:
            quality = "ELITE"
        elif tier == 2:
            quality = "PREMIUM"
        else:
            quality = "STANDARD"
        
        # Получаем репутацию
        node_hash = get_node_hash(node_data['node'])
        rep_count = self.reputation.get_count(node_hash)
        
        # Формируем имя
        name = f"[{protocol}] {index:04d} | T{tier} {quality} | REP:{rep_count} | SCORE:{score}"
        
        return name
    
    def save_results(self):
        """Сохраняет результаты в файлы"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 💾 Сохранение результатов...")
        
        # Разделяем по категориям
        tier1_nodes = []
        tier2_nodes = []
        ss_nodes = []
        all_nodes = []
        
        for idx, node_data in enumerate(self.checked_nodes):
            node = node_data['node']
            protocol = node_data['protocol']
            tier = node_data['tier']
            
            # Генерируем имя
            name = self.generate_server_name(node_data, idx + 1)
            full_node = f"{node}#{name}"
            
            # Распределяем по категориям
            all_nodes.append(full_node)
            
            if protocol == 'ss':
                ss_nodes.append(full_node)
            else:
                if tier == 1:
                    tier1_nodes.append(full_node)
                elif tier == 2:
                    tier2_nodes.append(full_node)
        
        # Сохраняем файлы
        files_saved = {}
        
        # ultra_elite.txt (Tier 1)
        self._save_file('ultra_elite.txt', tier1_nodes[:1000])
        files_saved['ultra_elite.txt'] = min(len(tier1_nodes), 1000)
        
        # hard_hidden.txt (Tier 1, топ-500)
        self._save_file('hard_hidden.txt', tier1_nodes[:500])
        files_saved['hard_hidden.txt'] = min(len(tier1_nodes), 500)
        
        # business.txt (копия hard_hidden)
        self._save_file('business.txt', tier1_nodes[:500])
        files_saved['business.txt'] = min(len(tier1_nodes), 500)
        
        # mob.txt (Tier 1+2, топ-1000)
        mobile_nodes = tier1_nodes + tier2_nodes
        self._save_file('mob.txt', mobile_nodes[:1000])
        files_saved['mob.txt'] = min(len(mobile_nodes), 1000)
        
        # med.txt (Tier 2, топ-2000)
        self._save_file('med.txt', tier2_nodes[:2000])
        files_saved['med.txt'] = min(len(tier2_nodes), 2000)
        
        # vls.txt (все VLESS/Trojan/Hysteria/TUIC)
        non_ss = [n for n in all_nodes if not n.startswith('ss://')]
        self._save_file('vls.txt', non_ss)
        files_saved['vls.txt'] = len(non_ss)
        
        # vless_vmess.txt (копия vls)
        self._save_file('vless_vmess.txt', non_ss)
        files_saved['vless_vmess.txt'] = len(non_ss)
        
        # ss.txt (Shadowsocks)
        self._save_file('ss.txt', ss_nodes[:2000])
        files_saved['ss.txt'] = min(len(ss_nodes), 2000)
        
        # all.txt (все ноды)
        self._save_file('all.txt', all_nodes[:25000])
        files_saved['all.txt'] = min(len(all_nodes), 25000)
        
        # sub.txt (копия all)
        self._save_file('sub.txt', all_nodes[:25000])
        files_saved['sub.txt'] = min(len(all_nodes), 25000)
        
        # all_configs.txt (копия all)
        self._save_file('all_configs.txt', all_nodes[:25000])
        files_saved['all_configs.txt'] = min(len(all_nodes), 25000)
        
        print("✅ Файлы сохранены:")
        for filename, count in files_saved.items():
            print(f"  📄 {filename}: {count} нод")
    
    def _save_file(self, filename: str, nodes: List[str]):
        """Вспомогательная функция сохранения файла"""
        try:
            if not nodes:
                # Создаем пустой файл
                with open(filename, 'w', encoding='utf-8') as f:
                    pass
                return
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(nodes))
        except Exception as e:
            print(f"❌ Ошибка сохранения {filename}: {e}")
    
    async def run(self):
        """Главный метод запуска"""
        start_time = time.time()
        
        print("=" * 70)
        print("🚀 АСИНХРОННЫЙ ПРОКСИ-АГРЕГАТОР")
        print("=" * 70)
        
        # 1. Загрузка источников
        await self.download_sources()
        
        # 2. Фильтрация и дедупликация
        self.filter_and_deduplicate()
        
        # 3. Расчет оценок
        self.calculate_scores()
        
        # 4. Проверка доступности
        await self.check_nodes()
        
        # 5. Обновление репутации
        self.update_reputation()
        
        # 6. Сохранение результатов
        self.save_results()
        
        elapsed = time.time() - start_time
        
        print("=" * 70)
        print(f"✅ ЗАВЕРШЕНО за {elapsed:.1f}s")
        print(f"📊 Статистика:")
        print(f"  - Загружено: {len(self.raw_nodes)} нод")
        print(f"  - После фильтрации: {len(self.filtered_nodes)} нод")
        print(f"  - После проверки: {len(self.checked_nodes)} нод")
        
        # Статистика по протоколам
        protocol_stats = {}
        for node_data in self.checked_nodes:
            proto = node_data['protocol']
            protocol_stats[proto] = protocol_stats.get(proto, 0) + 1
        
        print(f"  - По протоколам:")
        for proto, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"    • {proto.upper()}: {count}")
        
        print("=" * 70)

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

async def main():
    """Главная функция"""
    aggregator = ProxyAggregator()
    await aggregator.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Прервано пользователем")
    except Exception as e:
        print(f"\n❌ Критическая ошибка: {e}")
        import traceback
        traceback.print_exc() 
