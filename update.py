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
from collections import defaultdict

# Опциональные импорты
try:
    from ipaddress import ip_address, ip_network
    HAS_IPADDRESS = True
except ImportError:
    HAS_IPADDRESS = False

try:
    import validators
    HAS_VALIDATORS = True
except ImportError:
    HAS_VALIDATORS = False

try:
    import tldextract
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

ASN_BLACKLIST = {
    'hetzner', 'digitalocean', 'ovh', 'linode', 'vultr', 
    'contabo', 'amazon', 'google', 'microsoft', 'cloudflare',
    'scaleway', 'packet', 'leaseweb', 'quadranet', 'colocrossing'
}

VPN_NETWORKS = ['185.0.0.0/8', '45.0.0.0/8']

ALLOWED_PROTOCOLS = {'vless', 'hysteria2', 'hy2', 'tuic', 'ss', 'trojan'}

# ИСПРАВЛЕННЫЙ список методов Shadowsocks
MODERN_SS_METHODS = {
    '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm', 
    '2022-blake3-chacha20-poly1305',
    'aes-256-gcm',
    'chacha20-ietf-poly1305',
    'aes-128-gcm',
    'chacha20-poly1305'
}

USER_AGENTS = ['Happ/3.7.0', 'Happ/3.8.1', 'v2rayN/6.40']

ULTRA_ELITE_SNI = [
    "hls-svod.itunes.apple.com", "itunes.apple.com",
    "fastsync.xyz", "cloudlane.xyz", "powodzenia.xyz", 
    "stats.vk-portal.net", "akashi.vk-portal.net",
    "deepl.com", "www.samsung.com", "cdnjs.cloudflare.com",
    "st.ozone.ru", "disk.yandex.ru", "api.mindbox.ru",
    "egress.yandex.net", "sba.yandex.net", "goya.rutube.ru",
]

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

BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com']

ELITE_PORTS = {'2053', '2083', '2087', '2096', '8447', '9443', '10443', '443'}
SUSPICIOUS_PORTS = {'80', '8080', '3128', '1080', '8888'}

TCP_CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 15
MAX_NODES_TO_CHECK = 5000
MAX_CONCURRENT_CHECKS = 200

SOURCES = [
    "https://s3c3.001.gpucloud.ru/dggdu/xixz",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/config.txt", 
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    "https://vpn.yzewe.ru/1226960582/tVd6RXx-9V7q0SE8IjGxsw", 
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

# ============================================================================
# УТИЛИТЫ
# ============================================================================

def get_node_hash(node: str) -> str:
    base_link = node.split('#')[0]
    return hashlib.md5(base_link.encode()).hexdigest()

def extract_protocol(node: str) -> Optional[str]:
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
    try:
        match = re.search(r'[?&]sni=([^&?#\s]+)', node.lower())
        if match:
            return match.group(1).strip('.')
    except:
        pass
    return None

def extract_host_port(node: str) -> Optional[Tuple[str, int]]:
    try:
        parsed = urlparse(node)
        netloc = parsed.netloc.split('@')[-1]
        
        if ':' in netloc:
            host, port = netloc.rsplit(':', 1)
            return (host, int(port))
        else:
            return (netloc, 443)
    except:
        return None

def is_blacklisted_host(host: str) -> bool:
    host_lower = host.lower()
    return any(asn in host_lower for asn in ASN_BLACKLIST)

def validate_ss_method(node: str) -> bool:
    """ИСПРАВЛЕННАЯ валидация Shadowsocks"""
    try:
        # Сначала проверяем по строке (для современных форматов)
        node_lower = node.lower()
        for method in MODERN_SS_METHODS:
            if method in node_lower:
                return True
        
        # Пробуем декодировать base64
        base_part = node[5:].split('#')[0].split('?')[0]
        
        # Если есть @, то это формат method:password@host:port
        if '@' in base_part:
            try:
                decoded = base64.b64decode(base_part + '=' * (4 - len(base_part) % 4)).decode('utf-8', errors='ignore')
                method = decoded.split(':')[0].lower()
                return method in MODERN_SS_METHODS
            except:
                pass
        
        return False
    except:
        return False

def get_geo_simple(node: str) -> str:
    """Простая геолокация по домену (без DNS)"""
    try:
        parsed = urlparse(node)
        host = parsed.netloc.split('@')[-1].split(':')[0]
        
        if not host:
            return "UN"
        
        # IP - неизвестно
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            return "UN"
        
        # Домены
        if host.endswith(('.ru', '.su', '.рф')):
            return "RU"
        if host.endswith('.ua'):
            return "UA"
        if host.endswith('.kz'):
            return "KZ"
        if host.endswith('.tr'):
            return "TR"
        
        # Известные хосты
        if any(x in host for x in ['.yandex.', '.mail.', '.vk.', '.sber.', '.tinkoff.']):
            return "RU"
        
        return "UN"
    except:
        return "UN"

# ============================================================================
# РАСШИРЕННЫЕ ВАЛИДАТОРЫ
# ============================================================================

class EnhancedValidator:
    @staticmethod
    def validate_ip(ip: str) -> bool:
        if HAS_IPADDRESS:
            try:
                ip_obj = ip_address(ip)
                if ip_obj.is_private or ip_obj.is_reserved or ip_obj.is_loopback:
                    return False
                return True
            except:
                return False
        elif HAS_VALIDATORS:
            return validators.ipv4(ip) or validators.ipv6(ip)
        else:
            return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip))
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        if HAS_VALIDATORS:
            return validators.domain(domain)
        else:
            pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
            return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_port(port: int) -> bool:
        return 1 <= port <= 65535
    
    @staticmethod
    def is_in_vpn_network(ip: str) -> bool:
        if not HAS_IPADDRESS:
            return False
        try:
            ip_obj = ip_address(ip)
            for network_str in VPN_NETWORKS:
                network = ip_network(network_str, strict=False)
                if ip_obj in network:
                    return True
            return False
        except:
            return False
    
    @staticmethod
    def analyze_domain(domain: str) -> Dict:
        if HAS_TLDEXTRACT:
            ext = tldextract.extract(domain)
            return {
                'subdomain': ext.subdomain,
                'domain': ext.domain,
                'suffix': ext.suffix,
                'is_subdomain': bool(ext.subdomain),
                'levels': len(domain.split('.'))
            }
        else:
            parts = domain.split('.')
            return {
                'subdomain': parts[0] if len(parts) > 2 else '',
                'domain': parts[-2] if len(parts) > 1 else domain,
                'suffix': parts[-1] if len(parts) > 0 else '',
                'is_subdomain': len(parts) > 2,
                'levels': len(parts)
            }

# ============================================================================
# REPUTATION MANAGER
# ============================================================================

class ReputationManager:
    def __init__(self, reputation_file: str = 'reputation.json'):
        self.reputation_file = reputation_file
        self.reputation: Dict[str, Dict] = self._load()
        
    def _load(self) -> Dict:
        if os.path.exists(self.reputation_file):
            try:
                with open(self.reputation_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        if isinstance(v, int):
                            data[k] = {"count": v, "last_seen": int(time.time())}
                    return data
            except:
                return {}
        return {}
    
    def save(self):
        try:
            with open(self.reputation_file, 'w', encoding='utf-8') as f:
                json.dump(self.reputation, f, indent=2)
        except Exception as e:
            print(f"❌ Ошибка сохранения репутации: {e}")
    
    def update(self, node_hash: str):
        now = int(time.time())
        if node_hash not in self.reputation:
            self.reputation[node_hash] = {"count": 0, "last_seen": now}
        self.reputation[node_hash]["count"] += 1
        self.reputation[node_hash]["last_seen"] = now
    
    def get_count(self, node_hash: str) -> int:
        return self.reputation.get(node_hash, {}).get("count", 0)
    
    def cleanup(self, max_age_days: int = 30, max_entries: int = 10000):
        now = int(time.time())
        cutoff = now - (max_age_days * 86400)
        clean_db = {k: v for k, v in self.reputation.items() if v.get('last_seen', 0) > cutoff}
        if len(clean_db) > max_entries:
            sorted_rep = sorted(clean_db.items(), key=lambda x: x[1]['count'], reverse=True)
            clean_db = dict(sorted_rep[:max_entries])
        self.reputation = clean_db
    
    def clear(self):
        self.reputation = {}
        if os.path.exists(self.reputation_file):
            os.remove(self.reputation_file)
        print("✅ Репутация очищена")

# ============================================================================
# NODE SCORER
# ============================================================================

class NodeScorer:
    def __init__(self, reputation_manager: ReputationManager):
        self.reputation = reputation_manager
        self.validator = EnhancedValidator()
        self.uuid_counter: Dict[str, int] = {}
        self.sni_counter: Dict[str, int] = {}
        self.ip_counter: Dict[str, int] = {}
    
    def update_statistics(self, nodes: List[str]):
        self.uuid_counter.clear()
        self.sni_counter.clear()
        self.ip_counter.clear()
        
        for node in nodes:
            try:
                uuid = self._extract_uuid(node)
                if uuid:
                    self.uuid_counter[uuid] = self.uuid_counter.get(uuid, 0) + 1
                
                sni = extract_sni(node)
                if sni:
                    self.sni_counter[sni] = self.sni_counter.get(sni, 0) + 1
                
                host_port = extract_host_port(node)
                if host_port:
                    host, _ = host_port
                    if self.validator.validate_ip(host):
                        self.ip_counter[host] = self.ip_counter.get(host, 0) + 1
            except:
                continue
    
    def _extract_uuid(self, node: str) -> Optional[str]:
        try:
            if node.startswith('vmess://'):
                uuid_match = re.search(
                    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 
                    node, re.IGNORECASE
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
        score = 0
        n_l = node.lower()
        
        # Репутация
        node_hash = get_node_hash(node)
        rep_count = self.reputation.get_count(node_hash)
        score += rep_count * 50
        
        # Протокол
        protocol = extract_protocol(node)
        
        if protocol == 'hysteria2':
            score += 600
        elif protocol == 'vless':
            if 'flow=xtls-rprx-vision' in n_l:
                score += 500
            elif 'reality' in n_l:
                score += 400
            else:
                score += 200
        elif protocol == 'tuic':
            score += 450
        elif protocol == 'trojan':
            score += 150 if 'reality' not in n_l else 350
        
        # Транспорты
        if 'type=grpc' in n_l:
            score += 100
        if 'type=ws' in n_l:
            score += 50
        
        # Порты
        host_port = extract_host_port(node)
        if host_port:
            host, port = host_port
            
            if not self.validator.validate_port(port):
                score -= 500
            
            if str(port) in SUSPICIOUS_PORTS:
                score -= 200
            
            if str(port) in ELITE_PORTS:
                score += 250
            elif port == 443:
                score += 100
            
            if self.validator.validate_ip(host):
                if self.validator.is_in_vpn_network(host):
                    score -= 150
                
                ip_freq = self.ip_counter.get(host, 0)
                if ip_freq == 1:
                    score += 100
                elif ip_freq <= 3:
                    score += 50
            
            elif self.validator.validate_domain(host):
                domain_info = self.validator.analyze_domain(host)
                if domain_info['is_subdomain']:
                    score += 80
                if domain_info['levels'] >= 4:
                    score += 50
        
        # SNI
        sni = extract_sni(node)
        if sni:
            if any(black in sni for black in BLACK_SNI):
                score -= 2000
            
            if any(elite in sni for elite in ULTRA_ELITE_SNI):
                score += 300
            
            if any(target == sni or sni.endswith('.' + target) for target in TARGET_SNI):
                score += 200
            
            sni_freq = self.sni_counter.get(sni, 0)
            if sni_freq <= 5:
                score += 100
            
            if self.validator.validate_domain(sni):
                sni_info = self.validator.analyze_domain(sni)
                if sni_info['levels'] >= 3:
                    score += 80
        
        # UUID
        uuid = self._extract_uuid(node)
        if uuid:
            uuid_freq = self.uuid_counter.get(uuid, 0)
            if uuid_freq >= 10:
                score += 150
            elif uuid_freq >= 5:
                score += 80
            elif uuid_freq == 1:
                score += 100
        
        # ALPN
        if 'alpn=h3' in n_l:
            score += 60
        elif 'alpn=h2' in n_l:
            score += 30
        
        # Fingerprint
        if any(fp in n_l for fp in ['fp=safari', 'fp=ios', 'fp=firefox', 'fp=edge']):
            score += 50
        
        return max(score, 0)
    
    def get_tier(self, score: int, protocol: str) -> int:
        """Тир - только для метки качества"""
        if score >= 500:
            return 1
        elif score >= 300:
            return 2
        elif score >= 150:
            return 3
        return 4
class EnhancedNodeFilter:
    def __init__(self):
        self.validator = EnhancedValidator()
    
    def is_valid_protocol(self, node: str) -> bool:
        protocol = extract_protocol(node)
        
        if protocol == 'ss':
            return validate_ss_method(node)
        
        return protocol in ALLOWED_PROTOCOLS
    
    def is_blacklisted(self, node: str) -> bool:
        if any(trash in node for trash in ["0.0.0.0", "127.0.0.1", "localhost"]):
            return True
        
        host_port = extract_host_port(node)
        if host_port:
            host, port = host_port
            
            if is_blacklisted_host(host):
                return True
            
            if self.validator.validate_ip(host):
                pass
            elif not self.validator.validate_domain(host):
                return True
            
            if str(port) in SUSPICIOUS_PORTS:
                return True
        
        sni = extract_sni(node)
        if sni:
            if any(black in sni for black in BLACK_SNI):
                return True
            if not self.validator.validate_domain(sni):
                return True
        
        return False
    
    def clean_node(self, node: str) -> str:
        return node.split('#')[0]
    
    def deduplicate_key(self, node: str) -> str:
        try:
            protocol = extract_protocol(node)
            host_port = extract_host_port(node)
            
            if host_port:
                host, port = host_port
                return f"{protocol}:{host}:{port}"
        except:
            pass
        
        return get_node_hash(node)
    
    def parse_nodes_from_text(self, text: str) -> List[str]:
        nodes = []
        
        if "://" not in text[:100]:
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                text = decoded
            except:
                pass
        
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(('/', '#', ';', '//')):
                continue
            
            if any(proto in line for proto in ['://', 'ss://', 'vless://', 'trojan://', 'hysteria2://', 'tuic://']):
                line = line.replace('\x00', '').replace('\r', '')
                nodes.append(line)
        
        return nodes
    
    def validate_node_structure(self, node: str) -> bool:
        try:
            if HAS_VALIDATORS:
                base_node = node.split('#')[0]
                if not validators.url(base_node):
                    return False
            
            host_port = extract_host_port(node)
            if not host_port:
                return False
            
            host, port = host_port
            
            if not host or not self.validator.validate_port(port):
                return False
            
            return True
        except:
            return False

# ============================================================================
# ASYNC TCP CHECKER С СТАТИСТИКОЙ ИСТОЧНИКОВ
# ============================================================================

class AsyncTCPChecker:
    def __init__(self, timeout: float = TCP_CONNECT_TIMEOUT, max_concurrent: int = MAX_CONCURRENT_CHECKS):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.results = {}
        self.metrics = {
            'checked': 0,
            'alive': 0,
            'dead': 0,
            'errors': 0
        }
        # НОВОЕ: статистика по источникам и хостам
        self.source_stats = defaultdict(lambda: {'total': 0, 'alive': 0})
        self.host_stats = defaultdict(lambda: {'total': 0, 'alive': 0})
    
    async def check_port(self, host: str, port: int) -> Tuple[bool, Optional[float]]:
        async with self.semaphore:
            try:
                start = time.time()
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                elapsed = time.time() - start
                
                writer.close()
                await writer.wait_closed()
                
                self.metrics['alive'] += 1
                return (True, elapsed)
            
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                self.metrics['dead'] += 1
                return (False, None)
            except Exception:
                self.metrics['errors'] += 1
                return (False, None)
            finally:
                self.metrics['checked'] += 1
    
    async def check_node(self, node: str, source: str = 'unknown') -> Tuple[str, bool, Optional[float], str]:
        """Проверяет ноду и запоминает источник"""
        host_port = extract_host_port(node)
        
        if not host_port:
            return (node, False, None, source)
        
        host, port = host_port
        
        # Кэш
        cache_key = f"{host}:{port}"
        if cache_key in self.results:
            is_alive, latency = self.results[cache_key]
            
            # Обновляем статистику
            self.source_stats[source]['total'] += 1
            if is_alive:
                self.source_stats[source]['alive'] += 1
            
            self.host_stats[host]['total'] += 1
            if is_alive:
                self.host_stats[host]['alive'] += 1
            
            return (node, is_alive, latency, source)
        
        # Проверка
        is_alive, latency = await self.check_port(host, port)
        self.results[cache_key] = (is_alive, latency)
        
        # Статистика
        self.source_stats[source]['total'] += 1
        if is_alive:
            self.source_stats[source]['alive'] += 1
        
        self.host_stats[host]['total'] += 1
        if is_alive:
            self.host_stats[host]['alive'] += 1
        
        return (node, is_alive, latency, source)
    
    async def check_batch(self, nodes_with_sources: List[Tuple[str, str]]) -> List[Tuple[str, float, str]]:
        """Проверяет batch с информацией об источниках"""
        tasks = [self.check_node(node, source) for node, source in nodes_with_sources]
        results = await asyncio.gather(*tasks)
        
        alive_nodes = [
            (node, latency, source) for node, is_alive, latency, source in results 
            if is_alive
        ]
        
        return alive_nodes
    
    def get_metrics(self) -> Dict:
        return self.metrics.copy()
    
    def get_top_sources(self, top_n: int = 5) -> List[Tuple[str, int, int, float]]:
        """Возвращает ТОП источников по живым нодам"""
        source_list = []
        for source, stats in self.source_stats.items():
            total = stats['total']
            alive = stats['alive']
            rate = (alive / total * 100) if total > 0 else 0
            source_list.append((source, alive, total, rate))
        
        # Сортируем по количеству живых
        source_list.sort(key=lambda x: x[1], reverse=True)
        return source_list[:top_n]
    
    def get_top_hosts(self, top_n: int = 5) -> List[Tuple[str, int, int, float]]:
        """Возвращает ТОП хостов (ASN) по живым нодам"""
        host_list = []
        for host, stats in self.host_stats.items():
            total = stats['total']
            alive = stats['alive']
            rate = (alive / total * 100) if total > 0 else 0
            host_list.append((host, alive, total, rate))
        
        host_list.sort(key=lambda x: x[1], reverse=True)
        return host_list[:top_n]

# ============================================================================
# ASYNC DOWNLOADER
# ============================================================================

class AsyncDownloader:
    def __init__(self, timeout: int = HTTP_TIMEOUT):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.user_agent_idx = 0
        self.metrics = {
            'success': 0,
            'failed': 0,
            'timeout': 0
        }
    
    def _get_user_agent(self) -> str:
        ua = USER_AGENTS[self.user_agent_idx]
        self.user_agent_idx = (self.user_agent_idx + 1) % len(USER_AGENTS)
        return ua
    
    async def fetch(self, session: aiohttp.ClientSession, url: str) -> Tuple[str, str]:
        try:
            headers = {
                'User-Agent': self._get_user_agent(),
                'Accept': '*/*',
                'Accept-Encoding': 'gzip, deflate'
            }
            
            async with session.get(url, headers=headers, timeout=self.timeout) as response:
                if response.status == 200:
                    content = await response.text()
                    self.metrics['success'] += 1
                    return (url, content)
                else:
                    self.metrics['failed'] += 1
                    return (url, "")
        
        except asyncio.TimeoutError:
            self.metrics['timeout'] += 1
            return (url, "")
        except Exception:
            self.metrics['failed'] += 1
            return (url, "")
    
    async def fetch_all(self, urls: List[str]) -> List[Tuple[str, str]]:
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch(session, url) for url in urls]
            results = await asyncio.gather(*tasks)
            return results
    
    def get_metrics(self) -> Dict:
        return self.metrics.copy()

# ============================================================================
# ГЛАВНЫЙ АГРЕГАТОР
# ============================================================================

class EnhancedProxyAggregator:
    def __init__(self):
        self.reputation = ReputationManager()
        self.scorer = NodeScorer(self.reputation)
        self.filter = EnhancedNodeFilter()
        self.downloader = AsyncDownloader()
        self.checker = AsyncTCPChecker()
        
        self.raw_nodes: List[Dict] = []  # ИЗМЕНЕНО: храним {node, source}
        self.filtered_nodes: List[Dict] = []
        self.checked_nodes: List[Dict] = []
        
        self._print_available_libraries()
    
    def _print_available_libraries(self):
        print("📚 Доступные библиотеки:")
        libs = {
            'validators': HAS_VALIDATORS,
            'tldextract': HAS_TLDEXTRACT,
            'ipaddress': HAS_IPADDRESS
        }
        
        for lib, available in libs.items():
            status = "✅" if available else "❌"
            print(f"  {status} {lib}")
    
    async def download_sources(self):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 📥 Загрузка источников...")
        
        results = await self.downloader.fetch_all(SOURCES)
        
        total_nodes = 0
        for url, content in results:
            if not content:
                continue
            
            nodes = self.filter.parse_nodes_from_text(content)
            
            # Сохраняем источник для каждой ноды
            for node in nodes:
                self.raw_nodes.append({
                    'node': node,
                    'source': url
                })
            
            total_nodes += len(nodes)
            
            if len(nodes) > 0:
                url_short = url.split('/')[-1][:40]
                print(f"  ✓ {url_short}: {len(nodes)} нод")
        
        dl_metrics = self.downloader.get_metrics()
        print(f"📊 Загрузка: успешно={dl_metrics['success']}, "
              f"ошибки={dl_metrics['failed']}, таймауты={dl_metrics['timeout']}")
        print(f"📊 Всего загружено: {total_nodes} нод")
    
    def filter_and_deduplicate(self):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🔍 Фильтрация...")
        
        unique_map: Dict[str, Dict] = {}
        
        stats = {
            'blacklist': 0,
            'protocol': 0,
            'structure': 0,
            'duplicate': 0
        }
        
        processed = 0
        for item in self.raw_nodes:
            node = item['node']
            source = item['source']
            processed += 1
            
            if processed % 5000 == 0:
                print(f"  🔄 {processed}/{len(self.raw_nodes)}")
            
            clean_node = self.filter.clean_node(node)
            
            if not self.filter.validate_node_structure(clean_node):
                stats['structure'] += 1
                continue
            
            if self.filter.is_blacklisted(clean_node):
                stats['blacklist'] += 1
                continue
            
            if not self.filter.is_valid_protocol(clean_node):
                stats['protocol'] += 1
                continue
            
            dedup_key = self.filter.deduplicate_key(clean_node)
            
            if dedup_key in unique_map:
                stats['duplicate'] += 1
                continue
            
            protocol = extract_protocol(clean_node)
            unique_map[dedup_key] = {
                'node': clean_node,
                'protocol': protocol,
                'original': node,
                'source': source  # Сохраняем источник
            }
        
        self.filtered_nodes = list(unique_map.values())
        
        print(f"✅ Уникальных нод: {len(self.filtered_nodes)}")
        print(f"  📛 Отфильтровано: blacklist={stats['blacklist']}, "
              f"protocol={stats['protocol']}, structure={stats['structure']}, "
              f"duplicate={stats['duplicate']}")
    
    def calculate_scores(self):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 📊 Расчет оценок...")
        
        nodes_list = [n['node'] for n in self.filtered_nodes]
        self.scorer.update_statistics(nodes_list)
        
        for node_data in self.filtered_nodes:
            node = node_data['node']
            score = self.scorer.calculate_score(node)
            tier = self.scorer.get_tier(score, node_data['protocol'])
            
            node_data['score'] = score
            node_data['tier'] = tier
        
        # ИСПРАВЛЕНО: сортируем по score
        self.filtered_nodes.sort(key=lambda x: x['score'], reverse=True)
        
        print(f"✅ Оценки рассчитаны")
    
    async def check_nodes(self):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 🔌 TCP проверка...")
        
        nodes_to_check = self.filtered_nodes[:MAX_NODES_TO_CHECK]
        nodes_with_sources = [(n['node'], n['source']) for n in nodes_to_check]
        
        print(f"  📡 Проверка {len(nodes_with_sources)} нод...")
        
        alive_results = await self.checker.check_batch(nodes_with_sources)
        alive_map = {node: (latency, source) for node, latency, source in alive_results}
        
        for node_data in self.filtered_nodes:
            if node_data['node'] in alive_map:
                latency, source = alive_map[node_data['node']]
                node_data['latency'] = latency
                node_data['alive'] = True
            else:
                node_data['latency'] = None
                node_data['alive'] = False
        
        self.checked_nodes = [
            n for n in self.filtered_nodes 
            if n.get('alive', True)
        ]
        
        metrics = self.checker.get_metrics()
        print(f"✅ Проверка: живых={metrics['alive']}, "
              f"мертвых={metrics['dead']}, ошибок={metrics['errors']}")
        
        # НОВОЕ: ТОП-5 источников
        print(f"\n🏆 ТОП-5 источников по живым нодам:")
        top_sources = self.checker.get_top_sources(5)
        for i, (source, alive, total, rate) in enumerate(top_sources, 1):
            source_name = source.split('/')[-1][:50]
            print(f"  {i}. {source_name}")
            print(f"     Живых: {alive}/{total} ({rate:.1f}%)")
        
        # НОВОЕ: ТОП-5 хостов
        print(f"\n🏆 ТОП-5 хостов (ASN) по живым нодам:")
        top_hosts = self.checker.get_top_hosts(5)
        for i, (host, alive, total, rate) in enumerate(top_hosts, 1):
            print(f"  {i}. {host}")
            print(f"     Живых: {alive}/{total} ({rate:.1f}%)")
        
        print(f"\n📊 Итого нод: {len(self.checked_nodes)}")
    def update_reputation(self):
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 💾 Обновление репутации...")
        
        for node_data in self.checked_nodes:
            node_hash = get_node_hash(node_data['node'])
            self.reputation.update(node_hash)
        
        self.reputation.cleanup()
        self.reputation.save()
        
        print(f"✅ Репутация обновлена ({len(self.reputation.reputation)} записей)")
    
    def generate_server_name_hpp(self, node_data: Dict, index: int) -> str:
        """Генерирует имя с HPP неймингом и флагами"""
        protocol = node_data['protocol'].upper()
        score = node_data['score']
        tier = node_data['tier']
        latency = node_data.get('latency')
        node = node_data['node']
        
        # Геолокация
        geo = get_geo_simple(node)
        
        # Флаг страны
        if geo != "UN":
            try:
                flag = "".join(chr(ord(c.upper()) + 127397) for c in geo)
            except:
                flag = "🌐"
        else:
            flag = "🌐"
        
        # Качество
        if score >= 500:
            quality = "ELITE"
        elif score >= 300:
            quality = "PREMIUM"
        elif score >= 150:
            quality = "STANDARD"
        else:
            quality = "BASIC"
        
        # Репутация
        node_hash = get_node_hash(node)
        rep_count = self.reputation.get_count(node_hash)
        
        # Протокол тег
        protocol_tag = ""
        if protocol == 'HYSTERIA2':
            protocol_tag = "[HY2] "
        elif protocol == 'TUIC':
            protocol_tag = "[TUIC] "
        elif protocol == 'VLESS':
            if 'vision' in node.lower():
                protocol_tag = "[VISION] "
            elif 'reality' in node.lower():
                protocol_tag = "[REALITY] "
            else:
                protocol_tag = "[VLESS] "
        elif protocol == 'TROJAN':
            protocol_tag = "[TROJAN] "
        elif protocol == 'SS':
            protocol_tag = "[SS] "
        
        # ОРИГИНАЛЬНЫЙ HPP ФОРМАТ
        name = f"{flag} {protocol_tag}{geo}-{index:05d}-REP({rep_count})-HPP {quality}"
        
        return name
    
    def save_results(self):
        """Сохранение с правильным распределением по score"""
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 💾 Сохранение...")
        
        # Разделяем по протоколам
        ss_nodes = []
        non_ss_nodes = []
        
        for idx, node_data in enumerate(self.checked_nodes):
            node = node_data['node']
            protocol = node_data['protocol']
            
            # Генерируем HPP имя
            name = self.generate_server_name_hpp(node_data, idx + 1)
            full_node = f"{node}#{name}"
            
            if protocol == 'ss':
                ss_nodes.append(full_node)
            else:
                non_ss_nodes.append(full_node)
        
        # ИСПРАВЛЕНО: все файлы по score (уже отсортировано)
        all_nodes = ss_nodes + non_ss_nodes
        
        # Сохранение файлов
        files = {
            # Элитные (топ по score, любой протокол)
            'ultra_elite.txt': all_nodes[:1000],
            'hard_hidden.txt': all_nodes[:500],
            'business.txt': all_nodes[:500],
            
            # Мобильные и средние
            'mob.txt': all_nodes[:1000],
            'med.txt': all_nodes[1000:3000] if len(all_nodes) > 1000 else [],
            
            # По протоколам
            'vls.txt': non_ss_nodes,
            'vless_vmess.txt': non_ss_nodes,
            'ss.txt': ss_nodes[:2000],
            
            # Все
            'all.txt': all_nodes[:25000],
            'sub.txt': all_nodes[:25000],
            'all_configs.txt': all_nodes[:25000]
        }
        
        print("\n📄 Сохраненные файлы:")
        for filename, nodes in files.items():
            self._save_file(filename, nodes)
            print(f"  ✓ {filename}: {len(nodes)} нод")
    
    def _save_file(self, filename: str, nodes: List[str]):
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if nodes:
                    f.write('\n'.join(nodes))
        except Exception as e:
            print(f"  ❌ {filename}: {e}")
    
    async def run(self):
        """Главный запуск"""
        start = time.time()
        
        print("=" * 70)
        print("🚀 ФИНАЛЬНЫЙ АСИНХРОННЫЙ АГРЕГАТОР С HPP")
        print("=" * 70)
        
        await self.download_sources()
        self.filter_and_deduplicate()
        self.calculate_scores()
        await self.check_nodes()
        self.update_reputation()
        self.save_results()
        
        elapsed = time.time() - start
        
        print("\n" + "=" * 70)
        print(f"✅ ЗАВЕРШЕНО за {elapsed:.1f}s")
        print(f"\n📊 Итоговая статистика:")
        print(f"  - Загружено: {len(self.raw_nodes)} нод")
        print(f"  - После фильтрации: {len(self.filtered_nodes)} нод")
        print(f"  - После TCP check: {len(self.checked_nodes)} нод")
        print(f"  - Процент выживших: {len(self.checked_nodes)/len(self.raw_nodes)*100:.1f}%")
        
        # Статистика по протоколам
        proto_stats = {}
        tier_stats = defaultdict(int)
        score_ranges = {
            '1000+': 0,
            '500-999': 0,
            '300-499': 0,
            '150-299': 0,
            '0-149': 0
        }
        
        for n in self.checked_nodes:
            proto = n['protocol']
            proto_stats[proto] = proto_stats.get(proto, 0) + 1
            tier_stats[n['tier']] += 1
            
            score = n['score']
            if score >= 1000:
                score_ranges['1000+'] += 1
            elif score >= 500:
                score_ranges['500-999'] += 1
            elif score >= 300:
                score_ranges['300-499'] += 1
            elif score >= 150:
                score_ranges['150-299'] += 1
            else:
                score_ranges['0-149'] += 1
        
        print(f"\n  📊 По протоколам:")
        for proto, count in sorted(proto_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"    • {proto.upper()}: {count}")
        
        print(f"\n  🎯 По качеству (Tier):")
        for tier in sorted(tier_stats.keys()):
            print(f"    • Tier {tier}: {tier_stats[tier]} нод")
        
        print(f"\n  💯 По диапазонам score:")
        for range_name, count in score_ranges.items():
            print(f"    • {range_name}: {count}")
        
        # Топ-3 ноды
        print(f"\n  🏆 ТОП-3 ноды по score:")
        for i, node_data in enumerate(self.checked_nodes[:3], 1):
            protocol = node_data['protocol'].upper()
            score = node_data['score']
            geo = get_geo_simple(node_data['node'])
            print(f"    {i}. [{protocol}] {geo} | Score: {score}")
        
        print("=" * 70)

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

async def main():
    aggregator = EnhancedProxyAggregator()
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

