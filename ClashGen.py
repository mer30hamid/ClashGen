# Description: This script provides parsing v2ray/ss/ssr/trojan/clashR/clashX subscription link as Clash configuration file, which is only for learning and communication.
# Based on:
# https://github.com/Celeter/convert2clash

import errno
import shutil, os
import re
import sys
import json
import base64
import datetime
import requests
import yaml
import urllib.parse

from subprocess import Popen
# from datetime import datetime


options_path = os.path.join(os.getcwd(), "options.yaml")

if len(sys.argv)>1:
    if sys.argv[1]:
       options_path = sys.argv[1]

datetime_format = '%Y/%m/%d - %H:%M:%S'
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36"}


def log(msg):
    time = datetime.datetime.now()
    print('[' + time.strftime(datetime_format) + '] ' + msg)


# returns raw content of a file
def load_from_file(file_full_path):
    f = open(file_full_path, 'r', encoding="utf-8")
    content = f.read()
    f.close()
    return content

# save to file


def save_to_file(file_full_path, content, mode='w'):
    if not os.path.exists(os.path.dirname(file_full_path)):
        try:
            os.makedirs(os.path.dirname(file_full_path))
        except OSError as exc:  # Guard against race condition
            if exc.errno != errno.EEXIST:
                raise
    with open(file_full_path, mode) as f:
        f.write(content)


# Get the configuration file of the local rule policy
def load_local_config(path):
    try:
        f = open(path, 'r', encoding="utf-8")
        local_config = yaml.load(f.read(), Loader=yaml.FullLoader)
        f.close()
        return local_config
    except FileNotFoundError:
        log('Configuration file loading failed')
        sys.exit()

# Get Github latest release tag by github repo: <user>/<repo_name>
#example: get_github_latest_version('SamadiPour/iran-hosted-domains')


def get_github_latest_version(repo):
    return requests.get("https://api.github.com/repos/" + repo + "/releases/latest").json()["name"]

# Get the Iran hosted domains list


# base64 decoding
def safe_decode(s):
    num = len(s) % 4
    if num:
        s += '=' * (4 - num)
    return base64.urlsafe_b64decode(s)


# Parse vmess node
def decode_vmess_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[8:]
        if not decode_proxy or decode_proxy.isspace():
            log('vmess node information is empty, skip this node')
            continue
        proxy_str = base64.b64decode(decode_proxy).decode('utf-8')
        proxy_dict = json.loads(proxy_str)
        proxy_list.append(proxy_dict)
    return proxy_list

# Parse vless node


def decode_vless_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[8:]
        if not decode_proxy or decode_proxy.isspace():
            log('vless node information is empty, skip this node')
            continue
        proxy_str = base64.b64decode(decode_proxy).decode('utf-8')
        proxy_dict = json.loads(proxy_str)
        proxy_list.append(proxy_dict)
    return proxy_list


# Parse trojan node
def decode_trojan_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[9:]
        if not decode_proxy or decode_proxy.isspace():
            log('trojan node information is empty, skip this node')
            continue
        info = dict()
        param = decode_proxy
        if param.find('#') > -1:
            remark = urllib.parse.unquote(param[param.find('#') + 1:])
            info['name'] = remark
            param = param[:param.find('#')]
        if param.find('/?') > -1:
            plugin = urllib.parse.unquote(param[param.find('/?') + 2:])
            param = param[:param.find('/?')]
            for p in plugin.split(';'):
                key_value = p.split('=')
                info[key_value[0]] = key_value[1]
        if param.find('@') > -1:
            matcher = re.match(r'(.*?)@(.*):(.*)', param)
            if matcher:
                param = matcher.group(1)
                info['server'] = matcher.group(2)
                info['port'] = matcher.group(3)
            else:
                continue
            matcher = re.match(
                r'(.*?):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
            else:
                continue
        else:
            matcher = re.match(r'(.*?):(.*)@(.*):(.*)',
                               safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
                info['server'] = matcher.group(3)
                info['port'] = matcher.group(4)
            else:
                continue
        proxy_list.append(info)
    return proxy_list

# Parse ss node


def decode_ss_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[5:]
        if not decode_proxy or decode_proxy.isspace():
            log('ss node information is empty, skip this node')
            continue
        info = dict()
        param = decode_proxy
        if param.find('#') > -1:
            remark = urllib.parse.unquote(param[param.find('#') + 1:])
            info['name'] = remark
            param = param[:param.find('#')]
        if param.find('/?') > -1:
            plugin = urllib.parse.unquote(param[param.find('/?') + 2:])
            param = param[:param.find('/?')]
            for p in plugin.split(';'):
                key_value = p.split('=')
                info[key_value[0]] = key_value[1]
        if param.find('@') > -1:
            matcher = re.match(r'(.*?)@(.*):(.*)', param)
            if matcher:
                param = matcher.group(1)
                info['server'] = matcher.group(2)
                info['port'] = matcher.group(3)
            else:
                continue
            matcher = re.match(
                r'(.*?):(.*)', safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
            else:
                continue
        else:
            matcher = re.match(r'(.*?):(.*)@(.*):(.*)',
                               safe_decode(param).decode('utf-8'))
            if matcher:
                info['method'] = matcher.group(1)
                info['password'] = matcher.group(2)
                info['server'] = matcher.group(3)
                info['port'] = matcher.group(4)
            else:
                continue
        proxy_list.append(info)
    return proxy_list


# Parse ssr nodes
def decode_ssr_node(nodes):
    proxy_list = []
    for node in nodes:
        decode_proxy = node.decode('utf-8')[6:]
        if not decode_proxy or decode_proxy.isspace():
            log('ssr node The information is empty, skip this node')
            continue
        proxy_str = safe_decode(decode_proxy).decode('utf-8')
        parts = proxy_str.split(':')
        if len(parts) != 6:
            print('The ssr node failed to parse, link:{}'.format(node))
            continue
        info = {
            'server': parts[0],
            'port': parts[1],
            'protocol': parts[2],
            'method': parts[3],
            'obfs': parts[4]
        }
        password_params = parts[5].split('/?')
        info['password'] = safe_decode(password_params[0]).decode('utf-8')
        params = password_params[1].split('&')
        for p in params:
            key_value = p.split('=')
            info[key_value[0]] = safe_decode(key_value[1]).decode('utf-8')
        proxy_list.append(info)
    return proxy_list


# vmess convert to Clash node
def vmess_to_clash(arr):
    log('v2ray node is being converted...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        if item.get('ps') is None and item.get('add') is None and item.get('port') is None \
                and item.get('id') is None and item.get('aid') is None:
            continue
        obj = {
            'name': item.get('ps').strip() if item.get('ps') else None,
            'type': 'vmess',
            'server': item.get('add'),
            'port': int(item.get('port')),
            'uuid': item.get('id'),
            'alterId': item.get('aid'),
            'cipher': 'auto',
            'udp': True,
            # 'network': item['net'] if item['net'] and item['net'] != 'tcp' else None,
            'network': item.get('net'),
            'tls': True if item.get('tls') == 'tls' else None,
            'ws-path': item.get('path'),
            'ws-headers': {'Host': item.get('host')} if item.get('host') else None
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('alterId') is not None and not obj['name'].startswith('Remaining traffic') and not obj['name'].startswith('expiration time'):
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('Available vmess nodes {}'.format(len(proxies['proxy_names'])))
    return proxies

# vless convert to Clash node


def vless_to_clash(arr):
    log('vless node is being converted...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        if item.get('ps') is None and item.get('add') is None and item.get('port') is None \
                and item.get('id') is None and item.get('aid') is None:
            continue
        obj = {
            'name': item.get('ps').strip() if item.get('ps') else None,
            'type': 'vless',
            'server': item.get('add'),
            'port': int(item.get('port')),
            'uuid': item.get('id'),
            'alterId': item.get('aid'),
            'cipher': 'auto',
            'udp': True,
            # 'network': item['net'] if item['net'] and item['net'] != 'tcp' else None,
            'network': item.get('net'),
            'tls': True if item.get('tls') == 'tls' else None,
            'ws-path': item.get('path'),
            'ws-headers': {'Host': item.get('host')} if item.get('host') else None
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('alterId') is not None and not obj['name'].startswith('Remaining traffic') and not obj['name'].startswith('expiration time'):
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('Available vless nodes {}'.format(len(proxies['proxy_names'])))
    return proxies


# trojan is converted to Clash node
def trojan_to_clash(arr):
    log('trojan node converting...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('name').strip() if item.get('name') else None,
            'type': 'trojan',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'plugin': 'obfs' if item.get('plugin') and item.get('plugin').startswith('obfs') else None,
            'plugin-opts': {} if item.get('plugin') else None
        }
        if item.get('obfs'):
            obj['plugin-opts']['mode'] = item.get('obfs')
        if item.get('obfs-host'):
            obj['plugin-opts']['host'] = item.get('obfs-host')
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if not obj['name'].startswith('remaining traffic') and not obj['name'].startswith('expiration time'):
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('Available trojan nodes {}'.format(len(proxies['proxy_names'])))
    return proxies

# ss is converted to Clash node


def ss_to_clash(arr):
    log('ss node converting...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('name').strip() if item.get('name') else None,
            'type': 'ss',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'plugin': 'obfs' if item.get('plugin') and item.get('plugin').startswith('obfs') else None,
            'plugin-opts': {} if item.get('plugin') else None
        }
        if item.get('obfs'):
            obj['plugin-opts']['mode'] = item.get('obfs')
        if item.get('obfs-host'):
            obj['plugin-opts']['host'] = item.get('obfs-host')
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if not obj['name'].startswith('remaining traffic') and not obj['name'].startswith('expiration time'):
            proxies['proxy_list'].append(obj)
            proxies['proxy_names'].append(obj['name'])
    log('Available ss nodes {}'.format(len(proxies['proxy_names'])))
    return proxies


# ssr is converted into a Clash node
def ssr_to_clash(arr):
    log('ssr node conversion...')
    proxies = {
        'proxy_list': [],
        'proxy_names': []
    }
    for item in arr:
        obj = {
            'name': item.get('remarks').strip() if item.get('remarks') else None,
            'type': 'ssr',
            'server': item.get('server'),
            'port': int(item.get('port')),
            'cipher': item.get('method'),
            'password': item.get('password'),
            'obfs': item.get('obfs'),
            'protocol': item.get('protocol'),
            'obfs-param': item.get('obfsparam'),
            'protocol-param': item.get('protoparam'),
            'udp': True
        }
        for key in list(obj.keys()):
            if obj.get(key) is None:
                del obj[key]
        if obj.get('name'):
            if not obj['name'].startswith('Remaining traffic ') and not obj['name'].startswith('expiration time'):
                proxies['proxy_list'].append(obj)
                proxies['proxy_names'].append(obj['name'])
    log('available ssr node {} '.format(len(proxies['proxy_names'])))
    return proxies


# Get subscription address data:
def get_proxies(urls, options):
    url_list = urls.split(';')
    # headers = {
    #    'User-Agent': 'Clash For Python'
    # }
    proxy_list = {
        'proxy_list': [],
        'proxy_names': []
    }
    # Request subscription address
    for url in url_list:
        log("processing " + url)
        response = requests.get(url, headers=headers, timeout=9000).text
        try:
            raw = base64.b64decode(response)
        except Exception as r:
            log('base64 decoding failed: {}, should be clash node'.format(r))
            log('clash node extracting...')
            yml = yaml.load(response, Loader=yaml.FullLoader)
            nodes_list = []
            tmp_list = []
            # clash new field
            if yml.get('proxies'):
                tmp_list = yml.get('proxies')
            # clash old field
            elif yml.get('Proxy'):
                tmp_list = yml.get('Proxy')
            else:
                log('clash node extraction failed, the crash node is empty')
                continue
            for node in tmp_list:
                node['name'] = node['name'].strip(
                ) if node.get('name') else None
                # Yes clashR support
                if node.get('protocolparam'):
                    node['protocol-param'] = node['protocolparam']
                    del node['protocolparam']
                if node.get('obfsparam'):
                    node['obfs-param'] = node['obfsparam']
                    del node['obfsparam']
                node['udp'] = True
                nodes_list.append(node)
            node_names = [node.get('name') for node in nodes_list]
            log('Available crash nodes {}'.format(len(node_names)))
            proxy_list['proxy_list'].extend(nodes_list)
            proxy_list['proxy_names'].extend(node_names)
            continue
        nodes_list = raw.splitlines()
        vmess_urls = []
        vless_urls = []
        trojan_urls = []
        ss_urls = []
        ssr_urls = []
        for node in nodes_list:
            if node.startswith(b'vmess://'):
                vmess_urls.append(node)
            elif node.startswith(b'vless://'):
                vless_urls.append(node)
            elif node.startswith(b'trojan://'):
                trojan_urls.append(node)
            elif node.startswith(b'ss://'):
                ss_urls.append(node)
            elif node.startswith(b'ssr://'):
                ssr_urls.append(node)
            else:
                pass
        clash_node = {
            'proxy_list': [],
            'proxy_names': []
        }
        if len(vmess_urls) > 0:
            decode_proxy = decode_vmess_node(vmess_urls)
            node_temp = vmess_to_clash(decode_proxy)
            clash_node['proxy_list'] += node_temp['proxy_list']
            clash_node['proxy_names'] += node_temp['proxy_names']
        if len(vless_urls) > 0 and options['enable_vless']:
            decode_proxy = decode_vless_node(vless_urls)
            node_temp = vless_to_clash(decode_proxy)
            clash_node['proxy_list'] += node_temp['proxy_list']
            clash_node['proxy_names'] += node_temp['proxy_names']
        if len(trojan_urls) > 0 and options['enable_trojan']:
            decode_proxy = decode_trojan_node(trojan_urls)
            node_temp = trojan_to_clash(decode_proxy)
            clash_node['proxy_list'] += node_temp['proxy_list']
            clash_node['proxy_names'] += node_temp['proxy_names']
        if len(ss_urls) > 0:
            decode_proxy = decode_ss_node(ss_urls)
            node_temp = ss_to_clash(decode_proxy)
            clash_node['proxy_list'] += node_temp['proxy_list']
            clash_node['proxy_names'] += node_temp['proxy_names']
        if len(ssr_urls) > 0:
            decode_proxy = decode_ssr_node(ssr_urls)
            node_temp = ssr_to_clash(decode_proxy)
            clash_node['proxy_list'] += node_temp['proxy_list']
            clash_node['proxy_names'] += node_temp['proxy_names']
        proxy_list['proxy_list'].extend(clash_node['proxy_list'])
        proxy_list['proxy_names'].extend(clash_node['proxy_names'])
    log('Total found: {} nodes'. format(len(proxy_list['proxy_names'])))
    return proxy_list

# Get the configuration file of the rule policy


def get_default_config(url, path):
    try:
        raw = requests.get(url, timeout=5000).content.decode('utf-8')
        template_config = yaml.load(raw, Loader=yaml.FullLoader)
    except requests.exceptions.RequestException:
        log('Network acquisition rules Configuration failed, load local configuration file')
        template_config = load_local_config(path)
    log('got rule configuration file')
    return template_config


# Add proxy to configuration file
def add_proxies_to_model(data, model):
    if model.get('proxies') is None:
        model['proxies'] = data.get('proxy_list')
    else:
        model['proxies'].extend(data.get('proxy_list'))
    for group in model.get('proxy-groups'):
        if group.get('proxies') is None:
            group['proxies'] = data.get('proxy_names')
        else:
            group['proxies'].extend(data.get('proxy_names'))
    return model


# save the configuration file
def save_config(path, data):
    config = yaml.dump(data, sort_keys=False, default_flow_style=False,
                       encoding='utf-8', allow_unicode=True)
    save_to_file(path, config, mode='wb')
    if 'proxies' in data.keys():
        log('Update {} nodes successfully'.format(len(data['proxies'])))

# download and save lsit of domains for creating block list or white list
def get_domains(local_path, remote_path, min_valid_len):
    log('fetching domains...')
    try:
        Generate_from = remote_path
        raw = requests.get(Generate_from, timeout=5000).content.decode('utf-8')
        # raw content should not be small !
        if len(raw) < min_valid_len:
            raise ValueError("recieved content is not valid")
        save_to_file(local_path, raw)
        log('Success, file saved to: ' + local_path)
    except (requests.exceptions.RequestException, ValueError) as e:
        log('Error: ' + str(e))
        log('fetching domains faild, loading from local...')
        Generate_from = local_path
        if not os.path.exists(local_path):
            return ""
        raw = load_from_file(Generate_from)
        if len(raw) < min_valid_len:
            return ""
    return raw

# generate iranian domains clash (subconverter) rules and save in cache
def generate_iran_domains_rules(save_rules_path):
    min_valid_len = 5000
    raw = get_domains(
        local_path=options['iran-hosted-domains-file'],
        remote_path=options['iran-hosted-domains-link'],
        min_valid_len=min_valid_len,
    )
    if len(raw) < min_valid_len:
        log('Error: iranian domain list source is not available')
        sys.exit
    domain_list = raw.splitlines()
    log('generating iranian domain list...')
    file_content = ""
    for domain in domain_list:
        file_content += "DOMAIN-SUFFIX," + domain + '\n'
    save_to_file(save_rules_path, file_content)
    log('Sucess! iranian domain list saved to: ' + save_rules_path)

# generate iranian ads domains clash (subconverter) rules and save in cache
def generate_iran_ads_domains_rules(save_rules_path):
    min_valid_len = 5000
    raw = get_domains(
        local_path=options['iran-ads-domains-file'],
        remote_path=options['iran-ads-domains-link'],
        min_valid_len=min_valid_len,
    )
    if len(raw) < min_valid_len:
        log('Error: iranian domain list source is not available')
        sys.exit
    domain_list = raw.splitlines()
    log('generating iranian Ads domain list...')
    file_content = ""
    for domain in domain_list:
        if domain.startswith("#") or domain.startswith("[") or len(domain) < 2:
            continue
        file_content += "DOMAIN-SUFFIX," + domain + '\n'
    save_to_file(save_rules_path, file_content)
    log('Sucess! iranian domain list saved to: ' + save_rules_path)

# generate subconverter link
def get_subconverter_link(options):
    link = "http://"+ options['subconverter-ip-port'] +"/sub?"
    for p in options['subconvrter-options']:
        link += list(p.keys())[0] + "=" + list(p.values())[0] + "&"
    link += "url="
    for s in options['subscribe-links']:
        link += urllib.parse.quote(s, safe='')
        link += "|"
    link = link[:-1] # remove last "|"
    link += "&clash.dns=1"
    return link


# Program entry
if __name__ == '__main__':
    if not os.path.exists(options_path):
        log(f"Error: the options path: \"{options_path}\" does not exists.")
        sys.exit()
    options = load_local_config(options_path)
    lastupdate_file_path = os.path.join(
        options['cache-path'], "lastupdate.txt")
    try:
        cache_last_update = load_from_file(lastupdate_file_path)
        cache_last_update = datetime.datetime.strptime(
            cache_last_update, datetime_format).strftime(datetime_format)
    except (ValueError, FileNotFoundError) as e:
        cache_last_update = (datetime.datetime.now() - datetime.timedelta(days=100, seconds=15)).strftime(datetime_format)

    cache_age = datetime.datetime.now(
    ) - datetime.datetime.strptime(cache_last_update, datetime_format)
    
    # domain lists (rules) generated (will be geterated) placed in cache folder
    direct_domains_rules_path = os.path.join(options['cache-path'], 'subconverter/IranDomains.list')
    block_domains_rules_path = os.path.join(options['cache-path'], 'subconverter/IranAdsDomains.list')
    subconverter_rules_iran_path = os.path.dirname(os.path.abspath(options['subconverter-bin-path'])) + "/rules/Iran"
    os.makedirs(subconverter_rules_iran_path, exist_ok=True)
    
    # if cache_age is expired then generate lists again
    if cache_age.days > options['cache-lifetime']:
        generate_iran_domains_rules(direct_domains_rules_path)
        generate_iran_ads_domains_rules(block_domains_rules_path)
        cache_last_update = datetime.datetime.now().strftime(datetime_format)
        shutil.copy(direct_domains_rules_path, subconverter_rules_iran_path + "/IranDomains.list")
        shutil.copy(block_domains_rules_path, subconverter_rules_iran_path + "/PersianBlocker.list")
        save_to_file(lastupdate_file_path, cache_last_update)

    # force copy lists        
    if not os.path.exists(subconverter_rules_iran_path + "/IranDomains.list"):
       shutil.copy(direct_domains_rules_path, subconverter_rules_iran_path + "/IranDomains.list")
    if not os.path.exists(subconverter_rules_iran_path + "/PersianBlocker.list"):
       shutil.copy(block_domains_rules_path, subconverter_rules_iran_path + "/PersianBlocker.list")

    # Output path
    final_config_path = options['final-config-path']
    log("Starting subconverter...")
    subconverterP = Popen(options['subconverter-bin-path'])
    pythonHttpServerP = Popen('python -m http.server --bind 127.0.0.1 --directory ./ 10228')
    # ... do other stuff while subprocess is running
    test = get_subconverter_link(options)
    final_config = requests.get(get_subconverter_link(options), timeout=5000).content.decode('utf-8')
    # save_config(output_path, final_config)
    save_to_file(final_config_path, final_config)
    log(f'The file has been exported to {final_config_path}')
    pythonHttpServerP.terminate()
    subconverterP.terminate()
    
    
    # if sub_url is None or sub_url == '':
    #     sys.exit()
