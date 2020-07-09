from burp import IBurpExtender
from burp import ITab
from burp import IScannerCheck
from burp import IMessageEditorController
from burp import IParameter
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
from urlparse import urlparse
import re

jsonp_string = '&callback=jsonp1&cb=jsonp2&jsonp=jsonp3&jsonpcallback=jsonp4&jsonpcb=jsonp5&jsonp_cb=jsonp6&call=jsonp7&jcb=jsonp8&json=jsonp9'
jsonp_dict = {'callback':'jsonp1','cb':'jsonp2','jsonp':'jsonp3','jsonpcallback':'jsonp4','jsonpcb':'jsonp5','jsonp_cb':'jsonp6','call':'jsonp7','jcb':'jsonp8','json':'jsonp9'}
black_list = ['js','css','jpg','gif','png','zip','rar','bmp','jpeg','mp3','mp4','ico','txt']

"""
use for find jsonp feature in response just like callback({userinfo})
"""

class BurpExtender(IBurpExtender, ITab, IScannerCheck, IMessageEditorController, AbstractTableModel):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("JSONP Hunter")
        
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)

        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)
        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # register ourselves as an HTTP listener
        callbacks.registerScannerCheck(self)

        # id for column
        self.id = 0
        
        return
        
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "JsonpHunter"
    
    def getUiComponent(self):
        return self._splitpane
        
    #
    # implement IHttpListener
    #
    
    # def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
    #     # only process requests
    #     if messageIsRequest:
    #         return
        
    #     # create a new log entry with the message details
    #     self._lock.acquire()
    #     row = self._log.size()
    #     self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl()))
    #     self.fireTableRowsInserted(row, row)
    #     self._lock.release()

    # implement IScannerCheck

    def doActiveScan(self,baseRequestResponse,insertionPoint):
        pass

    def doPassiveScan(self,baseRequestResponse):
        self.baseRequestResponse = baseRequestResponse
        # service = baseRequestResponse.getHttpService()
        result = self.scancheck(baseRequestResponse)
        if result != [] and result !='' and result != None:
            param,url = result
            self.id +=1
            #analyze_request = self._helpers.analyzeRequest(service,baseRequestResponse.getRequest())
            self._lock.acquire()
            row = self._log.size()
            self._log.add(LogEntry(self.id,baseRequestResponse,param,url))
            self.fireTableRowsInserted(row, row)
            self._lock.release()
        return
    #
    # extend AbstractTableModel
    #
    
    def scancheck(self,baseRequestResponse):
        host,port,protocol,method,headers,params,url,reqBodys,analyze_request = self.Get_RequestInfo(baseRequestResponse)
        status_code,body = self.Get_ResponseInfo(baseRequestResponse)
        """
        deal with black_list if path like xxx.jpg or xxx.jpeg
        """
        parse_url = urlparse(url.toString())
        url_path = parse_url.path
        if url_path != '':
            if '.' in url_path:
                if url_path.split('.')[-1:][0] in black_list:
                    return ''

        if method == "GET":
            if params !='':
                """
                extract value in response use value({}) like jsonp
                """
                split_params = params.split('&')
                for param in split_params:
                    if '=' in param:
                        if len(param.split('=')) == 2:
                            key,value = param.split('=')
                            if value !='':
                                jsonp_pattern = value + '\(\{.*?\}\)'
                                re_result = re.findall(jsonp_pattern,body,re.S)
                                if re_result:
                                    return [key,url.toString()]
                """
                extract use jsonp_string
                """
                againReq_headers = headers
                againReq_headers[0] = headers[0].replace(params,params+jsonp_string)
                againReq =  self._helpers.buildHttpMessage(againReq_headers,reqBodys)
                if protocol == 'https':
                    is_https = True
                else:
                    is_https = False
                againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                analyze_againRes = self._helpers.analyzeResponse(againRes)
                againResBodys = againRes[analyze_againRes.getBodyOffset():].tostring()
                for key,value in jsonp_dict.items():
                    jsonp_pattern = value + '\(\{.*?\}\)'
                    re_result = re.findall(jsonp_pattern,againResBodys,re.S)
                    if re_result:
                        link = againReq_headers[0].split(' ')[1]
                        host = againReq_headers[1].split(' ')[1]
                        url = protocol+'://'+host+link
                        return [key,str(url)]
                """
                extract use jsonp_string with no params
                """
            else:
                if '?' not in url.toString():
                    path = headers[0].split(' ')[1]
                    againReq_headers_use_noparam = headers
                    againReq_headers_use_noparam[0] = headers[0].replace('GET '+path,'GET '+path+'?'+jsonp_string[1:])
                    againReq = self._helpers.buildHttpMessage(againReq_headers_use_noparam, reqBodys)
                    if protocol == 'https':
                        is_https = True
                    else:
                        is_https = False
                    againRes = self._callbacks.makeHttpRequest(host, port, is_https, againReq)
                    analyze_againRes = self._helpers.analyzeResponse(againRes)
                    againResBodys = againRes[analyze_againRes.getBodyOffset():].tostring()
                    for key,value in jsonp_dict.items():
                        jsonp_pattern = value + '\(\{.*?\}\)'
                        re_result = re.findall(jsonp_pattern,againResBodys,re.S)
                        if re_result:
                            link = againReq_headers_use_noparam[0].split(' ')[1]
                            host = againReq_headers_use_noparam[1].split(' ')[1]
                            url = protocol+'://'+host+link
                            return [key,str(url)]
 
        return ''


    
    def Get_RequestInfo(self,baseRequestResponse):
        """
        extract about service
        """
        service = baseRequestResponse.getHttpService()
        host = service.getHost()
        port = service.getPort()
        protocol = service.getProtocol()
        """
        extract request
        """
        analyze_request = self._helpers.analyzeRequest(service,baseRequestResponse.getRequest())
        reqBodys = baseRequestResponse.getRequest()[analyze_request.getBodyOffset():].tostring()
        url = analyze_request.getUrl()
        headers = analyze_request.getHeaders()
        method = analyze_request.getMethod()
        params = [i for i in analyze_request.getParameters() if i.getType() == IParameter.PARAM_URL]
        extract_params = '&'.join([('%s=%s' % (c.getName(),c.getValue())) for c in params ])

        return host,port,protocol,method,headers,extract_params,url,reqBodys,analyze_request

    def Get_ResponseInfo(self,baseRequestResponse):
        """
        extract response
        """
        analyze_response = self._helpers.analyzeResponse(baseRequestResponse.getResponse())
        status_code = analyze_response.getStatusCode()
        body =  baseRequestResponse.getResponse()[analyze_response.getBodyOffset():].tostring()

        return status_code,body

    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0

    def getColumnCount(self):
        return 3

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "ID"
        if columnIndex == 1:
            return "PARAM"
        if columnIndex == 2:
            return "URL"
        return ""

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return logEntry._id
        if columnIndex == 1:
            return logEntry._param
        if columnIndex == 2:
            return logEntry._url
        
        return ""

    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #
    
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()

#
# extend JTable to handle cell selection
#
    
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):
    
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse
        
        JTable.changeSelection(self, row, col, toggle, extend)
    
#
# class to hold details of each log entry
#

class LogEntry:
    def __init__(self,record_id,requestResponse, param, url):
        self._id = record_id
        self._param = param
        self._requestResponse = requestResponse
        self._url = url
