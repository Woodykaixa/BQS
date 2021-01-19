import base64
import time

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from bs4 import BeautifulSoup
import config

s = requests.Session()
timestamp = int(time.time())

SessionHeader = {
    'User-Agent': ''
}

VpnLoginUrl = 'https://cas-443.webvpn.bjut.edu.cn/login?service=https%3A%2F%2Fwebvpn.bjut.edu.cn%2Fusers%2Fauth%2Fcas' \
              '%2Fcallback%3Furl'

JwPageUrl = 'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_slogin.html'
JwLoginUrl = f'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_slogin.html?time={timestamp}'
JwRsaKeyGen = f'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_getPublicKey.html?time={timestamp}'

JwQueryUrl = f'https://jwglxt-443.webvpn.bjut.edu.cn/cjcx/cjcx_cxDgXscj.html?doType=query&gnmkdm=N305005&' \
             f'su={config.USERNAME}'

NotifyUrl = f'https://sc.ftqq.com/{config.SCKEY}.send'

VpnLoggedIn = False
JwLoggedIn = False


def get_vpn_login_data():
    loginPageRes = s.get('http://www.webvpn.bjut.edu.cn')
    loginPageBs = BeautifulSoup(loginPageRes.text, features='html.parser')
    hiddenSecrets = loginPageBs.select('form .dl-btn input')
    lt = hiddenSecrets[0]['value']
    execution = hiddenSecrets[1]['value']
    _eventId = hiddenSecrets[2]['value']
    return {
        'lt': lt,
        'execution': execution,
        '_eventId': _eventId,
        'submit': '',
        'username': config.USERNAME,
        'password': config.VPN_PASSWORD
    }


def vpn_login(login_data):
    loginRes = s.post(VpnLoginUrl, data=login_data)
    if loginRes.url == VpnLoginUrl:
        print('login failed. check your username and password')
        return False
    VpnLoggedIn = True
    return True


def vpn_logout():
    print('vpn logout')
    VpnLoggedIn = False
    s.get('https://www.webvpn.bjut.edu.cn/users/sign_out')


def get_jw_login_data():
    res = s.get(JwPageUrl)
    soup = BeautifulSoup(res.text, 'html.parser')
    csrftoken = soup.select_one('form #csrftoken')['value']
    return {'csrftoken': csrftoken, 'language': 'zh_CN', 'yhm': config.USERNAME}


def base64_to_int(b64str: str):
    hexBytes = base64.b64decode(b64str)
    result = 0
    for b in hexBytes:
        result *= 256
        result += int(b)
    return result


def get_rsa_public_key():
    res = s.get(JwRsaKeyGen)
    data = res.json()
    n = base64_to_int(data['modulus'])
    e = base64_to_int(data['exponent'])
    key = RSA.construct((n, e))
    return PKCS1_v1_5.new(key)


def jw_login(data):
    res = s.post(JwLoginUrl, data)
    try:
        _ = res.url.index('https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/index_initMenu.html')
        JwLoggedIn = True
        return True
    except ValueError:
        return False


def jw_logout():
    print('jw logout')
    JwLoggedIn = False
    s.get(f'https://jwglxt-443.webvpn.bjut.edu.cn/logout?t={timestamp}&login_type=')


def query_score():
    data = {
        'xnm': config.YEAR,
        'xqm': config.TERM,
        '_search': 'false',
        'nd': timestamp,
        'queryModel.showCount': 30,
        'queryModel.currentPage': 1,
        'queryModel.sortName': 'cj',
        'queryModel.sortOrder': 'asc',
        'time': 1
    }
    res = s.post(JwQueryUrl, data)
    scoreItems = res.json()['items']
    print(f'fetched {len(scoreItems)} scores')
    scores = {}
    for item in scoreItems:
        scores[item['kcmc']] = item['cj']
    return scores


def notify_score(score_dict):
    desc = '\n'.join(list(map(lambda x: f'+ {x}: {score_dict[x]}', score_dict)))
    data = {
        'text': 'bqs查询结果',
        'desc': desc
    }
    s.post(NotifyUrl, data)


def close(code):
    if JwLoggedIn:
        jw_logout()
    if VpnLoggedIn:
        vpn_logout()
    s.close()
    exit(code)


if __name__ == '__main__':
    if not config.ENABLE:
        close(0)
    vpnLoginData = get_vpn_login_data()
    if vpn_login(vpnLoginData):
        print('vpn login successful.')
        jwLoginData = get_jw_login_data()
        pk = get_rsa_public_key()
        cipher = base64.b64encode(pk.encrypt(config.JW_PASSWORD.encode()))
        jwLoginData['mm'] = cipher
        if jw_login(jwLoginData):
            print('jw login successful.')
            scores = query_score()
            if len(scores) != 0:
                notify_score(scores)
            close(0)
        else:
            print('jw login failed')
            close(1)

    else:
        close(1)
