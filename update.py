import requests, base64, re, os, socket, geoip2.database, json, hashlib, shutil, time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

# --- НАСТРОЙКИ ---
TARGET_SNI = list(set([
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
]))

BLACK_SNI = ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'porn']
ELITE_PORTS = ['2053', '2083', '2087', '2096']
CHAMPION_HOSTS = ['yandex', 'selectel', 'timeweb', 'firstbyte', 'gcore', 'vkcloud', 'mail.ru']

urls = [
    # Твои личные S3 источники
    "https://s3c3.001.gpucloud.ru/dg68glfr8yyyrm9hoob72l3gdu/xicrftxzsnsz",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
    
    # igareck (White & Black Lists Rus)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Cable.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_SS%2BAll_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    
    # zieng2 (WL specialized)
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    
    # 55prosek-lgtm
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/55prosek-lgtm/vpn_config_for_russia/refs/heads/main/blacklist.txt",
    
    # vlesscollector
    "https://raw.githubusercontent.com/vlesscollector/vlesscollector/refs/heads/main/vless_configs.txt",
    
    # Стандартные агрегаторы
    "https://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt",
    "https://fsub.flux.2bd.net/githubmirror/bypass-unsecure/bypass-unsecure-all.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/vmess.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/trojan.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/tuic.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/ssr.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hysteria2.txt",
    "https://fsub.flux.2bd.net/githubmirror/split-by-protocols/hy2.txt",
    "https://sub-aggregator.vercel.app/",

    # Goida Vpn Configs (AvenCores) - прописал их циклом для чистоты
    *[f"https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/{i}.txt" for i in range(1, 27)]
]

class MetaAggregator:
    def __init__(self):
        self.rep_path = 'reputation.json'
        self.reputation = self._load_json(self.rep_path)
        self.geo_cache = {}
        self.reader = geoip2.database.Reader('GeoLite2-Country.mmdb') if os.path.exists('GeoLite2-Country.mmdb') else None

    def _load_json(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for k, v in data.items():
                        if isinstance(v, int): data[k] = {"count": v, "last_seen": int(time.time())}
                    return data
            except: return {}
        return {}

    def get_node_id(self, node):
        return hashlib.md5(node.split('#')[0].encode()).hexdigest()

    def get_fp(self, node):
        hash_val = int(self.get_node_id(node), 16)
        choice = hash_val % 100
        if choice < 65: return "chrome"
        if choice < 85: return "edge"
        if choice < 95: return "safari"
        return "ios"

    def calculate_score(self, node):
        score = 0
        n_l = node.lower()
        parsed = urlparse(node)
        
        node_id = self.get_node_id(node)
        rep_data = self.reputation.get(node_id, {})
        score += rep_data.get('count', 0) * 50

        if 'xtls-rprx-vision' in n_l: score += 150
        if any(p in n_l for p in ['type=xhttp', 'mode=stream-up', 'tuic', 'hysteria2', 'hy2']): score += 250
        if 'trojan' in n_l: score += 100
        
        port = parsed.netloc.split(':')[-1] if ':' in parsed.netloc else '443'
        if port in ELITE_PORTS: score += 250
        elif port == '443': score += 100

        sni_match = re.search(r'sni=([^&?#\s]+)', n_l)
        if sni_match:
            sni = sni_match.group(1).strip('.')
            if any(s in sni for s in BLACK_SNI): score -= 2000
            if any(ts == sni or sni.endswith('.'+ts) for ts in TARGET_SNI): score += 300
        
        if any(h in parsed.netloc for h in CHAMPION_HOSTS): score += 50
        return score

    def patch(self, node):
        try:
            parsed = urlparse(node)
            query = parse_qs(parsed.query)
            if node.startswith(('vless', 'vmess', 'trojan')):
                query['fp'] = [self.get_fp(node)]
                if 'alpn' not in query: query['alpn'] = ['h2,http/1.1']
                net_type = query.get('type', [''])[0]
                if net_type == 'ws' and 'path' not in query: query['path'] = ['/graphql']
                if net_type == 'grpc' and 'serviceName' not in query: query['serviceName'] = ['grpc']
            
            new_query = urlencode(query, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        except: return node

    def get_geo(self, node):
        try:
            parsed = urlparse(node)
            host = parsed.netloc.split('@')[-1].split(':')[0]
            if not host: return "UN"
            if host in self.geo_cache: return self.geo_cache[host]
            
            ip = socket.gethostbyname(host) if not re.match(r"^\d", host) else host
            code = "UN"
            if self.reader:
                try:
                    res = self.reader.country(ip)
                    if res.country.iso_code: code = res.country.iso_code
                except: pass
            self.geo_cache[host] = code
            return code
        except: return "UN"

    def cleanup_reputation(self, max_age_days=30, max_entries=10000):
        now = int(time.time())
        cutoff = now - (max_age_days * 86400)
        clean_db = {k: v for k, v in self.reputation.items() if v.get('last_seen', 0) > cutoff}
        if len(clean_db) > max_entries:
            sorted_rep = sorted(clean_db.items(), key=lambda x: x[1]['count'], reverse=True)
            clean_db = dict(sorted_rep[:max_entries])
        self.reputation = clean_db

def main():
    agg = MetaAggregator()
    
    def fetch(url):
        try: return requests.get(url, timeout=15).text
        except: return ""
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚡ Сбор источников...")
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(fetch, urls))
    
    raw_nodes = []
    for content in results:
        if "://" not in content[:100]:
            try: content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except: pass
        raw_nodes.extend([l.strip() for l in content.splitlines() if "://" in l and not l.startswith("//")])

    unique_map = {}
    for node in raw_nodes:
        # Фильтрация мусорных IP
        if any(trash in node for trash in ["0.0.0.0", "127.0.0.1"]):
            continue
            
        try:
            # Отрезаем всё лишнее сразу (чистим хвост #)
            base_link = node.split('#')[0]
            p = urlparse(base_link)
            ip_key = f"{p.scheme}@{p.netloc.split('@')[-1].split(':')[0]}"
            score = agg.calculate_score(base_link)
            if ip_key not in unique_map or score > unique_map[ip_key]['score']:
                unique_map[ip_key] = {'node': base_link, 'score': score}
        except: continue
    
    sorted_nodes = sorted(unique_map.values(), key=lambda x: x['score'], reverse=True)
    all_unique = [v['node'] for v in sorted_nodes]

    vless_pool = [n for n in all_unique if not n.startswith('ss://')][:5000]
    ss_pool = [n for n in all_unique if n.startswith('ss://')]
    
    processed_vless = []
    now_ts = int(time.time())
    
    print("Обработка воронки ТОП-5000...")
    for i, node in enumerate(vless_pool):
        node_id_hash = agg.get_node_id(node)
        rep_entry = agg.reputation.get(node_id_hash, {"count": 0, "last_seen": now_ts})
        rep_entry["count"] += 1
        rep_entry["last_seen"] = now_ts
        agg.reputation[node_id_hash] = rep_entry
        
        geo = agg.get_geo(node)
        patched = agg.patch(node)
        score = agg.calculate_score(node)
        
        rep_val = rep_entry["count"]
        geo_str = str(geo) if geo else "UN"
        flag = "".join(chr(ord(c.upper()) + 127397) for c in geo_str) if geo_str != "UN" else "🌐"
        
        # ЭТАЛОННЫЙ НЕЙМИНГ: 🇷🇺 RU-00001-REP(1)-HPP ELITE
        name = f"{flag} {geo_str}-{i+1:05}-REP({rep_val})-HPP ELITE"
        
        processed_vless.append({'node': f"{patched}#{name}", 'geo': geo_str, 'score': score, 'raw': node})

    def save(file, data):
        if not data: return
        with open(file, 'w', encoding='utf-8') as f: f.write("\n".join(data))
        print(f"💾 {file}: {len(data)}")

    save("hard_hidden.txt", [n['node'] for n in processed_vless[:1000] if n['score'] >= 500])
    save("mob.txt", [n['node'] for n in processed_vless if n['score'] >= 300][:1000])
    save("med.txt", [n['node'] for n in processed_vless if 150 <= n['score'] < 450][:2000])
    save("vls.txt", [n['node'] for n in processed_vless])
    save("ss.txt", [n for n in ss_pool if agg.get_geo(n) != "RU"][:2000])
    save("all.txt", all_unique[:25000])
    save("whitelist_cable.txt", [n['node'] for n in processed_vless if 'cable' in n['raw'].lower()])
    save("whitelist_mobile.txt", [n['node'] for n in processed_vless if 'mobile' in n['raw'].lower()])

    try:
        shutil.copy("hard_hidden.txt", "business.txt")
        shutil.copy("vls.txt", "vless_vmess.txt")
        shutil.copy("all.txt", "sub.txt")
        shutil.copy("all.txt", "all_configs.txt")
    except: pass

    agg.cleanup_reputation()
    with open(agg.rep_path, 'w', encoding='utf-8') as f:
        json.dump(agg.reputation, f, indent=2)
        
    if agg.reader: agg.reader.close()
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🚀 Скрипт завершен.")

if __name__ == "__main__":
    main()
 

