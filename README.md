# BurpSuite 插件

所有插件都是用python2开发的

## SQL注入检测插件

暂时只能检测报错注入和延时注入

一定要加载模块目录

![](./imgs/SQL/0.png)

加载插件,将xml目录放在Passive_SQL_Check.py同目录下

![](./imgs/SQL/1.png)

出现successful说明成功加载，此时如果errors出现报错无视即可。

![](./imgs/SQL/2.png)

此时被动扫描检测注入插件已经运行，只要我们burp抓的数据包，都会经过被动扫描插件检测每个参数是否存在注入

包含：get，post，cookies里的各个参数

当我访问注入靶场的时候，插件自动对参数id检测是否存在注入。

当检测出注入时，打印格式为：

```
dbms -> 数据库
ReqMethod -> 请求方法
ReqUrl -> 请求的url
parameter -> 存在注入的参数
parameterValue -> payload
regexp_ret -> 正则匹配的结果
```

```
[+] [Error] dbms: [MySQL]
ReqMethod: [GET]
ReqUrl: [http://192.168.168.139/sqli/Less-20/index.php]
parameter: [uname]
parameterValue: [admin`%20--%20\]
regexp_ret: [SQL syntax; check the manual that corresponds to your MySQL]

[+] [Time] dbms: [MySQL]
ReqMethod: [GET]
ReqUrl: [http://192.168.168.139/sqli/Less-20/index.php]
parameter: [uname]
parameterValue: [admin'%2bSLEEP(0.0)%2b']
regexp_ret: [None]

[+] [Error] dbms: [MySQL]
ReqMethod: [POST]
ReqUrl: [http://192.168.168.139/sqli/Less-11/]
parameter: [passwd]
parameterValue: [pass'))%20waitfor%20delay%20'0:0:8'%20--s]
regexp_ret: [SQL syntax; check the manual that corresponds to your MySQL]
```

如下图，检测出Mysql的报错注入和延时注入-post类型

![](./imgs/SQL/3.png)

如下图，检测出MSSQL的报错注入和延时注入

![](./imgs/SQL/7.png)

如下图，检测出Oracle的报错注入和延时注入

![](./imgs/SQL/9.png)

此时会在当前目录下生成2个文件：isSQL.txt和sqlChecked.txt

![](./imgs/SQL/4.png)

isSQL.txt文件保存注入点：报错类型，正则匹配结果，payload，请求头，响应包

这样我们就可以根据保存的内容，还原数据包

![](./imgs/SQL/5.png)

![](./imgs/SQL/10.png)

sqlChecked.txt保存检测过的数据包：请求方式，请求路径，参数名

这样就可以通过这三个数据类型过滤掉重复掉数据包，避免重复检测

![](./imgs/SQL/6.png)

如下图：检测出是同一个数据包，那么就不会调用payload重复测试
![](./imgs/SQL/8.png)

同时会在Scanner模块的报告里显示存在注入的数据包

![](./imgs/SQL/11.png)

![](./imgs/SQL/12.png)

![](./imgs/SQL/13.png)


## Fastjson RCE检测插件

加载Fastjson RCE插件后，当数据包的参数是json时，触发插件检测。

当检测出fastjson rce时，打印[+], 如果该数据包检测过，打印[checked]

![](./imgs/Fastjson/0.png)

检测过的url保存在当前的fastjsonChecked.txt里

![](./imgs/Fastjson/1.png)

存在漏洞的url保存在当前的isFastjsonRCE.txt里

![](./imgs/Fastjson/2.png)

在issue模块里显示存在漏洞的数据包

![](./imgs/Fastjson/3.png)

可以查看请求包

![](./imgs/Fastjson/4.png)


# 上传FUZZ插件

![](./imgs/Upload/8.png)

![](./imgs/Upload/9.png)

![](./imgs/Upload/10.png)

![](./imgs/Upload/1.png)

![](./imgs/Upload/2.png)

![](./imgs/Upload/3.png)

![](./imgs/Upload/4.png)

![](./imgs/Upload/5.png)

![](./imgs/Upload/6.png)

![](./imgs/Upload/7.png)


# Shiro插件

![](./imgs/Shiro/shiro1.png)

![](./imgs/Shiro/shiro2.png)

113444aaaa