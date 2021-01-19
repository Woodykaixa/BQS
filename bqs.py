import base64
import time
import os
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

s.headers.update(SessionHeader)

VpnLoginUrl = 'https://cas-443.webvpn.bjut.edu.cn/login?service=https%3A%2F%2Fwebvpn.bjut.edu.cn%2Fusers%2Fauth%2Fcas' \
              '%2Fcallback%3Furl'

JwPageUrl = 'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_slogin.html'
JwLoginUrl = f'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_slogin.html?time={timestamp}'
JwRsaKeyGen = f'https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/login_getPublicKey.html?time={timestamp}'

JwQueryUrl = f'https://jwglxt-443.webvpn.bjut.edu.cn/cjcx/cjcx_cxDgXscj.html?doType=query&gnmkdm=N305005&' \
             f'su={config.USERNAME}'

NotifyUrl = f'https://sc.ftqq.com/{config.SCKEY}.send'


class CloseHelper:
    VpnLoggedIn = False
    JwLoggedIn = False


def try_get(url):
    for i in range(10):
        try:
            res = s.get(url)
            return res
        except requests.ConnectionError as e:
            time.sleep(5)
            if i == 9:
                raise e
            continue


def try_post(url, data):
    for i in range(10):
        try:
            res = s.post(url, data)
            return res
        except requests.ConnectionError as e:
            time.sleep(5)
            if i == 9:
                raise e
            continue


def get_vpn_login_data():
    loginPageRes = try_get('http://www.webvpn.bjut.edu.cn')
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
    loginRes = try_post(VpnLoginUrl, login_data)
    if loginRes.url == VpnLoginUrl:
        print('login failed. check your username and password')
        return False
    CloseHelper.VpnLoggedIn = True
    return True


def vpn_logout():
    print('vpn logout')
    CloseHelper.VpnLoggedIn = False
    try_get('https://www.webvpn.bjut.edu.cn/users/sign_out')


def get_jw_login_data():
    res = try_get(JwPageUrl)
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
    res = try_get(JwRsaKeyGen)
    data = res.json()
    n = base64_to_int(data['modulus'])
    e = base64_to_int(data['exponent'])
    key = RSA.construct((n, e))
    return PKCS1_v1_5.new(key)


def jw_login(data):
    res = try_post(JwLoginUrl, data)
    try:
        _ = res.url.index('https://jwglxt-443.webvpn.bjut.edu.cn/xtgl/index_initMenu.html')
        CloseHelper.JwLoggedIn = True
        return True
    except ValueError:
        return False


def jw_logout():
    print('jw logout')
    CloseHelper.JwLoggedIn = False
    try_get(f'https://jwglxt-443.webvpn.bjut.edu.cn/logout?t={timestamp}&login_type=')


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
    res = try_post(JwQueryUrl, data)
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
    try_post(NotifyUrl, data)


def close(code):
    if CloseHelper.JwLoggedIn:
        jw_logout()
    if CloseHelper.VpnLoggedIn:
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
