#!/usr/bin/python3
import random
import re
import string
import urllib
import urllib.parse
import urllib.request
import requests
import time
from lib.core.engine import generate_taskid

class XSSchecker(object):
    REGULAR_PATTERNS = (
        (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
        (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'), "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
        (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'), "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", r"\\'"),
        (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'), "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", r'\\"'),
        (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',), "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
        (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering",
         r"(?s)<script.+?</script>|<!--.*?-->"),
        (r"<[^>]*=\s*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',),
         "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering",
         r"(?s)<script.+?</script>|<!--.*?-->|\\"),
        (r'<[^>]*=\s*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',),
         "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering",
         r"(?s)<script.+?</script>|<!--.*?-->|\\"),
        (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering",
         r"(?s)<script.+?</script>|<!--.*?-->|=\s*'[^']*'|=\s*\"[^\"]*\""),
    )
    DOM_PATTERNS =(
        r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
        r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
    )
    DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"
    SMALLER_CHAR_POOL = ('<', '>')
    LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')

    def __init__(self, url, cookie="", data=""):
        """

        :param url: 目标url
        :param cookie: 若需要测试登陆后的页面需要填写
        :param data: 测试POST参数时填写，格式为key1=value1&key2=value2
        """
        self.headers = {
            "Cookie": cookie,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36",
            "Referer": ""
        }
        self.target = url
        self.taskid = generate_taskid()
        self.task_start_time = None  # 任务开启时间
        self.task_type = "XSS"
        self.status = "not running"  # 任务当前的状态not running为未开启，running正在扫描，terminated扫描结束
        self.data = data
        self.task_result = {"target": url, "task_type": "XSS", "task_data": {}}

    # 发送请求，返回响应内容
    def get_response(self, url, data=""):
        encode_url = "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in range(len(url)))  # url编码

        # data需要转换为键值对的字典，下列代码将普通post数据转换为字典
        # 示例："name=abc&password=123"  => {'name': 'abc', 'password': '123'}
        data_dic = {}
        if "&" in data:
            for i in data.split("&"):
                data_dic[i.split("=")[0]] = i.split("=")[1]
        elif "=" in data:
            data_dic[data.split("=")[0]] = data.split("=")[1]
        # print("data_dic=", data_dic)

        # 根据data是否传值判断请求方法发送请求并接收响应
        res = requests.get(encode_url, headers=self.headers) if not data else requests.post(encode_url, headers=self.headers, data=data_dic)
        return res.content.decode('utf8'), res.status_code  # 返回响应的源代码及状态码(源代码, 状态码)

    # 确定不可被过滤的字符在响应中是否被过滤
    def contains(self, content, chars):
        content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
        return all(char in content for char in chars)

    # 扫描主程序
    def start_task(self):
        """
        DOM-XSS检测思路：

        经过后端的XSS检测思路：
        对获取url中的get请求参数以及post请求参数，对get参数依次进行large_char_pool和small_char_pool检测，如get参数有name=1&id=99，则先对name进行检测id无payload，第二次对id进行检测name无payload
        post参数检测类型get参数检测。示例如下：
            待测url：http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1&id=99  POST-data：username=usr&password=psd
            参数：?name=1
            * scanning GET parameter 'name'
            tampered：http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1%27btexk%3E%3C%3B%27%22dhxje&id=99
            tampered：http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1btexk%3E%3Cdhxje&id=99
            参数：&id=99
            * scanning GET parameter 'id'
            tampered：http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1&id=99%27extdy%22%3C%3E%3B%27socpm
            tampered：http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1&id=99extdy%3C%3Esocpm
            参数：username=usr
            * scanning POST parameter 'username'
            tampered：username=usr%27avnjd%27%22%3B%3C%3Eotxyp&password=psd
            tampered：username=usravnjd%3E%3Cotxyp&password=psd
            参数：&password=psd
            * scanning POST parameter 'password'
            tampered：username=usr&password=psd%27bmpae%27%3B%3C%3E%22mublt
            tampered：username=usr&password=psdbmpae%3C%3Emublt
        :return:存在XSS返回True，不存在返回False，目标站点访问失败返回None
        """
        self.task_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))  # 获取当前时间，即开启扫描的时间
        self.task_result["start_time"] = self.task_start_time  # 将扫描时间添加到扫描结果中
        has_xss, usable = False, False  # has_xss表示是否含有xss漏洞，usable表示url或post-data中是否存在键值对

        # --------DOM-XSS检测----------
        # 将响应中的DOM_FILTER_REGEX去掉，包括单引号、双引号的内容，escape()函数，注释
        original = re.sub(XSSchecker.DOM_FILTER_REGEX, "", self.get_response(self.target)[0])
        # print("original：\n"+original)
        # 在orifinal中寻找dom结构，如<script>var (abc)=document.location;...document.write(..abc..)..</script>
        dom = next(filter(None, (re.search(_, original) for _ in XSSchecker.DOM_PATTERNS)), None)
        # 根据dom_filter_regex去掉响应包中的内容，然后在响应中查找dom_patterns，如果存在，则提示可能存在dom-xss
        if dom:
            print(" (i) page itself appears to be XSS vulnerable (DOM)")
            print("  (o) ...%s..." % dom.group(0))  # 匹配正则表达式整体结果
            has_xss = True

        # ----------经过后端的xss检测---------
        # 分别进行GET和POST请求
        for phase in ("GET", "POST"):  # phase为请求方法
            # 如果当前为GET请求则current为url，如果为POST请求若data传入则current为data，data未传入则current为空
            current = self.target if phase == "GET" else (self.data or "")
            # print("current："+current)  http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1#
            # and中含0，返回0，均为非0时，返回后一个值。or中，至少有一个非0时，返回第一个非0

            # 在url或post-data中查找参数的键值对，遍历每个参数对参数进行测试
            for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):  # re.finditer返回的是迭代器
                # print("参数："+match.group())  # ?name=1
                found, usable = False, True  # fount为true说明找到了存在漏洞的参数，usable为true说明url或post-data中存在键值对
                # print("* scanning %s parameter '%s'" % (phase, match.group("parameter")))  # 打印正在通过哪种请求方法测试哪个参数
                # 获取payload的前缀及后缀
                # 随机生成5个小写字母，string.ascii_lowercase表示所有的小写字母，random.sample随机从小写字母中抽取指定数目个片段(列表)
                prefix, suffix = ("".join(random.sample(string.ascii_lowercase, 5)) for i in range(2))

                # larger_char_pool=(''', '"', '>', '<', ';') smaller_char_pool=('<', '>')
                for pool in (XSSchecker.LARGER_CHAR_POOL, XSSchecker.SMALLER_CHAR_POOL):  # 针对larger_char_pool和smaller_char_pool进行单独的测试
                    if not found:  # 如果参数存在
                        # 构造payload
                        # payload格式为prefix + pool中所有字符的随机排序 + suffix
                        # 如果这个pool是larger_char_pool，则这里在payload之前加一个单引号'
                        # 原因如下：
                        # 1).试图触发xss
                        # 2).故意构造一个错误的sql语句用于报错，试图在报错信息中寻找触发点
                        tampered = current.replace(match.group(0),  # ?name=1
                                                   "%s%s" % (match.group(0),  # ?id=99prefix'"><;suffix
                                                             urllib.parse.quote("%s%s%s%s" % (
                                                             "'" if pool == XSSchecker.LARGER_CHAR_POOL else "", prefix,
                                                             "".join(random.sample(pool, len(pool))), suffix))
                                                             )  # ?name=1'lrvem<">;'velyp为未编码，实际先进行url编码
                                                   )
                        # urllib.parse.quote对url进行url编码(%编码)
                        # print("tampered："+tampered)
                        # http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1%27lrvem%3C%22%3E%3B%27velyp#
                        # http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1lrvem%3C%3Evelyp#
                        content = (self.get_response(tampered)[0] if phase == "GET" else self.get_response(self.target, data=tampered)[0]).replace("%s%s" % ("'" if pool == XSSchecker.LARGER_CHAR_POOL else "", prefix), prefix)
                        # 构造完payload之后直接发送，然后获取返回内容。如果这个pool是larger_char_pool，那么这里就要去掉prefix之前的单引号'，这个单引号的作用刚刚已经说了，至此已经完成了它的使命，这里自然要从响应中去掉，防止干扰。

                        for regex, condition, info, content_removal_regex in XSSchecker.REGULAR_PATTERNS:
                            # 根据content_removal_regex去掉响应中的内容（因为payload有重合部分，所以要通过这种方式来避免重合的检测，即表中每个元组的第四个元素）
                            filtered = re.sub(content_removal_regex or "", "", content)  # 将content的内容根据contend_removal_regex正则去掉

                            # 在响应中寻找(prefix+...+suffix)，sample即为找到的response中的payload 如果可以找到，就说明这个参数的值是会被输出到响应中的
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), filtered, re.I):  # re.I表示忽略大小写
                                # 把response-payload添加到regex的chars位 检测这个参数是否可以利用
                                context = re.search(regex % {"chars": re.escape(sample.group(0))}, filtered, re.I)  # re.I表示忽略大小写，

                                # 检测payload被后端的过滤情况
                                if context and not found and sample.group(1).strip():
                                    if self.contains(sample.group(1), condition):  # 根据contains函数确定不可被过滤的字符在响应中是否被过滤
                                        # 如果没有被过滤，则认为可能存在XSS漏洞
                                        # print(" (i) %s parameter '%s' appears to be XSS vulnerable (%s)" % (phase,
                                        #                                                                     match.group("parameter"),
                                        #                                                                     info % dict((("filtering", "no" if all(char in sample.group(1) for char in XSSchecker.LARGER_CHAR_POOL) else "some"),))
                                        #                                                                     )
                                        #       )
                                        # all()函数用于判断给定的可迭代参数iterable中的所有元素是否都为TRUE，如果是返回True，否则返回False。元素除了是0、空、None、False外都算True。
                                        self.task_result['task_data'][phase+" parameter："+match.group("parameter")] = info % dict((("filtering", "no" if all(char in sample.group(1) for char in XSSchecker.LARGER_CHAR_POOL) else "some"),))
                                        # task_data格式为：{GET parameter：name:">.xss.<", outside of tags, no filtering}
                                        # print(self.task_result)  # {'target': 'http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1&id=99', 'task_type': 'XSS', 'task_data': {'GET parameter：name': '">.xss.<", outside of tags, no filtering'}}
                                        found = has_xss = True
                                    break
        if not usable:
            print(" (x) no usable GET/POST parameters found")
        return has_xss


if __name__ == "__main__":
    method = "GET"
    headers = {
        "Cookie": "security=low; PHPSESSID=kiqairv77e0l4lqkacn3tb8mi5",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.92 Safari/537.36",
        "Referer": ""
    }
    url = "http://192.168.1.14/DVWA-master/vulnerabilities/xss_r/?name=1&id=99"
    data = "username=usr&password=psd"
    cookie = "security=low; PHPSESSID=933d1tl08tpp5rt43hqv8i8jf2"
    test = XSSchecker(url=url, cookie=cookie, data=data)
    # print(test.taskid)  # 打印任务id
    test.start_task()
    # print(test.task_result)  # 打印任务结果