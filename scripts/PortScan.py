#!/usr/bin/python3
from scapy.all import *
from lib.core.engine import generate_taskid
from queue import Queue


# 域名解析
def domain2ip(domain):
    # 该函数的参数只能传入域名，若传入URL则抛出异常.如http://test.com，test.com/，末尾不能添加/
    # 正确格式：https://www.example.com
    ip = socket.gethostbyname(domain.split("www.")[1])
    return ip


# 将用户指定的端口表达式添加到端口列表中
def get_port_queue(specify_port_range):
    """匹配用户指定的端口范围
    将用户指定的端口表达式添加到端口队列中
    如："1-2 3,4,5 6" => [1, 2, 3, 4, 5, 6]
    :param specify_port_range: str (用户指定的表达式，如："1-2 3,4,5 6") 可以重复，函数可去重
    :return: 队列 端口队列(元素为用户指定的所有端口)
    """
    lis = specify_port_range.strip().split(" ")  # 对用户指定的端口范围去除两边的空格之后以字符串之间的空格进行分隔(返回列表)
    # 定义匹配a-b a,b,c a的正则表达式
    r1 = r'\d+-\d+'  # 匹配 a-b类型
    r2 = r'(\d+,(\d+,)*\d+)'  # 匹配a,b类型
    r3 = r'\d+'  # 匹配a类型
    # 定义完整的用于扫描的端口列表
    port_range_lis = []  # 定义端口列表用于检测重复
    port_range_queue = Queue(65535)  # 定义待扫描端口队列
    for port in lis:  # 对分隔出的每个部分进行匹配并添加到端口列表中
        if len(re.findall(r1, port)) > 0:  # 如果a-b类型的匹配成功则执行下面代码
            a = re.findall(r3, re.findall(r1, port)[0])  # 找出a-b中的a和b
            for i in range(int(a[0]), int(a[1])+1):  # 将指定a-b范围的元素添加到列表中
                if i not in port_range_lis:
                    port_range_lis.append(i)
                    port_range_queue.put(i)
        elif len(re.findall(r2, port)) > 0:  # 如果a,b类型的匹配成功则执行下面代码
            a = re.findall(r3, port)
            for i in a:
                if i not in port_range_lis:
                    port_range_lis.append(int(i))
                    port_range_queue.put(int(i))
        else:  # 如果a类型的匹配成功则执行下面代码
            if port not in port_range_lis:  # 判断是否在端口列表中，若不在则添加到列表中
                port_range_lis.append(int(port))
                port_range_queue.put(int(port))
    return port_range_queue  # 返回待扫描端口队列用于扫描


# 多线程扫描函数
def multithreading_port_scan(task_object, port_queue, scan_threads, scan_mode, data_process_object):
    """开启多线程端口扫描

    :param task_object: object Portscan对象 new_task = Portscan(192.168.1.1)
    :param port_queue: queue 待扫描端口队列 使用get_port_queue函数格式化的参数
    :param scan_threads: int 扫描线程
    :param scan_mode: str 扫描方法
    :return: 若开启扫描则在扫描结束后返回扫描结果{taskid: open_port_list}，若未执行扫描即任务id为None则返回None
    """
    print("启动端口扫描")
    if task_object.taskid is not None:
        data_process_object.alter_data(status="running")  # 将状态改为正在扫描
        task_object.task_start_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        task_object.status = "running"
        threads = []  # 定义线程列表用于存放每个定义的线程
        for i in range(scan_threads):  # 循环创建指定线程数的线程
            if scan_mode == "SOCKET":
                t = threading.Thread(target=task_object.start_scan, args=(port_queue, task_object.port_scan_socket))
            elif scan_mode == "TCP":
                t = threading.Thread(target=task_object.start_scan, args=(port_queue, task_object.port_scan_sS))
            elif scan_mode == "UDP":
                t = threading.Thread(target=task_object.start_scan, args=(port_queue, task_object.port_scan_sU))
            threads.append(t)  # 将创建的线程添加到线程列表用于后边对线程的操作
        for t in threads:  # 遍历线程列表，开启每个线程
            t.start()
        for t in threads:  # 遍历线程列表，将每个线程设置为阻塞
            t.join()
        # 因为线程设置了阻塞，所以下列代码(格式化扫描结果)将在端口扫描结束之后执行
        task_object.task_result[task_object.taskid] = task_object.open_port_list
        task_object.task_result["start_time"] = task_object.task_start_time
        task_object.status = "terminated"
        data_process_object.alter_data(result=task_object.task_result, status="terminated")  # 将状态改为扫描结束 并将扫描结果进行修改
        return task_object.task_result  # 扫描成功则返回字典
    return None  # 未执行扫描则返回None


# 主机发现
def host_is_live(ip):
    """判断目标主机是否存活
    先通过三层ICMP尝试，ICMP未发现则尝试四层TCP，四层TCP未发现则尝试四层UDP
    :param ip: 目标主机的ip地址
    :return: 存活返回True，未存活返回False
    """
    # 三层主机发现,通过判断
    print("ping start")
    ping_response = sr1(IP(dst=ip)/ICMP(), timeout=2, verbose=0)
    if ping_response:  # 首先通过三层发现ICMP Ping，若探测到目标主机则返回True
        print("ping end")
        return True
    else:  # 若三层主机发现未发现则尝试TCP四层发现
        print("tcp start")
        tcp_response = sr1(IP(dst=ip)/TCP(dport=56789, flags='A'), timeout=2, verbose=0)
        if tcp_response:
            print("tcp end")
            return True  # 若通过四层主机发现探测到主机则返回True
        else:  # 若四层TCP主机发现未发现主机，则尝试UDP四层发现
            print("udp start")
            udp_response = sr1(IP(dst=ip)/UDP(dport=56789), timeout=2, verbose=0)
            if udp_response:
                print("udp end")
                return True  # UDP主机发现发现主机则返回True
            else:
                print("all down")
                return False  # 通过三层ICMP、四层TCP、四层UDP均未发现，则返回False


# 定义端口扫描类
class PortScan(object):
    """
    ip为字符串类型
    port为int类型
    """
    # 定义端口列表
    default_port_list = "1-65535"

    def __init__(self, ip):
        self.ip = ip  # 目标ip
        self.target = ip  # 扫描目标
        self.task_type = "PORT"
        self.taskid = None  # 任务id
        self.task_start_time = None  # 任务开启时间
        self.open_port_list = []  # 开启的端口列表
        self.status = "not running"  # 任务当前的状态not running为未开启，running正在扫描，terminated扫描结束
        self.task_result = {"target": ip, "task_type": "PORT"}  # 扫描结果存储在字典中，键为任务id，值为开放的列表

    # 创建任务id，若taskid生成则返回taskid，未执行生成方法即taskid有值则返回False
    def create_port_scan_task(self):
        if self.taskid is None:
            self.taskid = generate_taskid()
            return self.taskid
        return False

    # 开启扫描
    def start_scan(self, queue, mode):
        """多线程调用扫描方法函数
        :param queue: queue 待扫描端口队列
        :param mode: object.method 扫描的方法 如new_task.port_scan_sS
        :return: 无返回值
        """
        while not queue.empty():
            mode(queue.get())

    # socket端口扫描
    def port_scan_socket(self, port):  # port为int类型
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        try:
            s.connect((self.ip, port))
            if port not in self.open_port_list:
                self.open_port_list.append(port)
            return True
        except:
            return False

    # 使用scapy进行TCP—SYN半开扫描
    def port_scan_sS(self, port):
        tcp_response = sr1(IP(dst=self.ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if int(tcp_response[TCP].flags) == 18:  # 根据标志位的数值判断，18表示SA，即SYN+ACK
            if port not in self.open_port_list:
                self.open_port_list.append(port)
            return True
        elif int(tcp_response[TCP].flags) == 20:  # 20表示RA，即RST+ACK
            return False

    # 使用scapy进行UDP端口扫描
    def port_scan_sU(self, port):
        udp_response = sr1(IP(dst=self.ip)/UDP(dport=port), timeout=1, verbose=0)
        if udp_response is None:
            if port not in self.open_port_list:
                self.open_port_list.append(port)
            return True
        else:
            return False


if __name__ == "__main__":
    print(host_is_live(domain2ip("http://www.yunsee.cn")))
