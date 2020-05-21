# Flame Dragon Scanning System

![logo](https://github.com/BeatRex/Flame-Dragon-Scanning-System/blob/master/static/images/scanner_icon.png)
![Python版本](https://badgen.net/badge/Python/3.8.0/green)
![Flask版本](https://badgen.net/badge/Flask/1.1.0/yellow)
![MySQL版本](https://badgen.net/badge/MySQL/5.5.53/blue)

***

## 项目说明

本项目集成URL爬取、端口扫描、SQL注入扫描、XSS扫描功能，SQL注入扫描调用<a href="https://github.com/sqlmapproject/sqlmap">sqlmapapi</a>，XSS扫描代码参考自sqlmap作者编写的XSS扫描工具<a href="https://github.com/stamparm/DSXS">DSXS</a>。
项目仍在完善中，欢迎各位大佬指点。

***

## 搭建步骤

1. 初始化数据库：在项目文件夹内运行CMD，执行python manager.py db init
2. 创建用户：运行项目，Flask默认运行在127.0.0.1:5000，访问127.0.0.1:5000/useradd界面添加用户，用户添加成功后会自动跳转至登录页面。
3. 下载sqlmap：https://github.com/sqlmapproject/sqlmap
4. 开启sqlmapapi服务：进入到sqlmap所在文件夹，打开CMD，执行python sqlmapapi.py -s

***

## 个人平台

### 微信公众号：BeatRex的成长记录
<img src="https://github.com/BeatRex/Flame-Dragon-Scanning-System/blob/master/static/images/wxgzh.jpg">

### 技术博客：<a href="https://blog.csdn.net/BeatRex">https://blog.csdn.net/BeatRex</a>

### BiliBili：<a href="https://space.bilibili.com/263536932">https://space.bilibili.com/263536932</a>

### 网易云音乐：<a href="https://music.163.com/#/user/home?id=318198925">BeatRex</a>
