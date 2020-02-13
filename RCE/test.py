# -*-coding:utf-8 -*-
import requests

headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36'}

# 获取dnslog地址
def get_dnslog():
    getdomain_url = r'http://www.dnslog.cn/getdomain.php'
    try:
        res = requests.get(url=getdomain_url, headers=headers)
        cookies = res.cookies
        dnslog_domain = res.text  # dnslog地址
        for cookie in cookies:
            name, value = cookie.name, cookie.value
            if name == 'PHPSESSID':
                getrecords_cookie = {}
                getrecords_cookie[name] = value  # 刷新dnslog所需要的cookies
                return getrecords_cookie, dnslog_domain
    except Exception as e:
        print('dnslog Address acquisition failed, please re-run the script')  # dnslog地址获取失败，请重新运行脚本

# 刷新dnslog，查看是否有数据
def records_dnslog(random_str):
    getrecords_url = r'http://www.dnslog.cn/getrecords.php'
    res = requests.get(url=getrecords_url, cookies=getrecords_cookie, headers=headers)
    if random_str in res.text:
        return True
    else:
        return False

getrecords_cookie, dnslog_domain = get_dnslog()
print getrecords_cookie, dnslog_domain