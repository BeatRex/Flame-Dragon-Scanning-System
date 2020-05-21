import requests
from urllib.parse import urljoin, urlparse
from lxml import etree
from queue import Queue
from lib.core.engine import generate_taskid
from pybloom_live import ScalableBloomFilter  # 导入布隆过滤器模块
import time


class Crawler(object):
    # 请求头
    request_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36"
    }

    def __init__(self, start_url):
        self.start_url = start_url  # 开始爬取的url http://www.example.com/
        self.target = start_url  # 扫描的目标
        self.task_type = "CRAWL"  # 扫描的类型
        self.scheme = urlparse(start_url)[0]  # 获取协议 http
        self.domain = urlparse(start_url)[1].split("w.")[1]  # 获取域名 example.com
        self.url_queue = Queue(1000)  # 初始化url队列
        self.url_list = []  # 定义爬取的url
        self.url_queue.put(start_url)  # 先将开始爬取的url添加到待爬取队列中
        self.bloom_filter = ScalableBloomFilter(initial_capacity=1000)  # 定义布隆过滤器，在入队之前首先判断，防止将url重复入队
        self.bloom_filter.add(start_url)
        self.task_start_time = None  # 任务启动时间 格式为：2020-03-29 13:31:06
        self.status = "not running"  # 任务当前的状态not running为未开启，running正在扫描，terminated扫描结束
        self.taskid = generate_taskid()  # 任务id
        self.task_result = {"target": start_url, "task_type": "CRAWL"}  # 定义格式化的扫描结果{taskid: url_list}

    # 根据域名进行url过滤(过滤掉非本域名下的url)
    def url_filter_domain(self, url):  # 过滤url
        if url.find(self.domain) != -1:  # 判断域名是否在待过滤的url中
            return url  # 如果属于本域名则返回url
        return None  # 如果不属于本域名或其他则返回None

    def url_crawl_total(self):  # url爬取,爬取整站的url
        """宽度优先爬取整站url
        思路：1.如果队列不为空则从队列中取出url
        2.判断取出的url是否在已经爬取过的url列表中，若不在则对该url进行爬取并将该url添加到url列表
        3.将爬取到的url进行格式化-过滤-判断是否在url列表中，若满足则入队
        :return:
        """
        self.task_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.status = "running"
        while not self.url_queue.empty():  # 设置while循环，若队列不为空则反复执行
            current_url = self.url_queue.get()  # 从队列中取出url
            # 判断队列中取出的url是否被爬取过，如果
            if current_url not in self.url_list:
                # print("添加到url列表中", current_url)
                self.url_list.append(current_url)  # 将访问过的url添加到url列表中
                # print("%s添加到url列表中" %current_url)
                res = requests.get(current_url, headers=self.request_headers)  # 向当前url发送请求
                target_html = etree.HTML(res.content)  # 实例化xpath解析对象
                page_a_list = target_html.xpath("//a/@href")  # 获取所有a标签的href属性值
                # -----需要先对url进行过滤
                # 待完善
                for url in page_a_list:
                    format_url = urljoin(current_url, url)  # 格式化url，第一个参数为当前访问页面的url，第二个为本页面提取到的a标签的href
                    # 过滤url(如果结果不为None则说明属于本域名下的url)
                    if self.url_filter_domain(format_url) is not None and format_url not in self.url_list:
                        if format_url not in self.bloom_filter:  # 如果url未在布隆过滤器中则将url添加到布隆过滤器中
                            self.bloom_filter.add(format_url)
                            # print("添加到队列中：", format_url)
                            self.url_queue.put(format_url)  # 将url添加到队列中
        self.task_result[self.taskid] = self.url_list
        self.task_result["start_time"] = self.task_start_time
        self.status = "terminated"
        return self.task_result

    def url_crawl_one(self):  # url爬取单页的url
        self.task_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        self.status = "running"
        current_url = self.url_queue.get()  # 从队列中取出url
        res = requests.get(current_url, headers=self.request_headers)  # 向当前url发送请求
        target_html = etree.HTML(res.content)  # 实例化xpath解析对象
        page_a_list = target_html.xpath("//a/@href")  # 获取所有a标签的href属性值
        for url in page_a_list:
            format_url = urljoin(current_url, url)  # 格式化url，第一个参数为当前访问页面的url，第二个为本页面提取到的a标签的href
            # 过滤url(如果结果不为None则说明属于本域名下的url)
            if self.url_filter_domain(format_url) is not None and format_url not in self.url_list:
                self.url_list.append(format_url)  # 将url添加到url_list列表中
        self.task_result[self.taskid] = self.url_list
        self.task_result["start_time"] = self.task_start_time
        self.status = "terminated"
        return self.task_result


if __name__ == '__main__':
    test = Crawler("http://www.aaa.com/url_crawl/index.html")
    print(test.url_crawl_total())