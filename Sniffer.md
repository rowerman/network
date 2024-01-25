## 项目名称：网络嗅探器

### 0. 项目概述

本项目开发的平台为Ubuntu22.04虚拟机，使用Python3.9编写

实现的功能包括：

* 指定监听的网卡捕获进出本机的数据报
* 对捕获的数据报进行分解，分析其各层使用的协议及各层的关键信息
* 将分片的IP数据报进行重组
* 将捕获的数据报信息保存至用户指定的文件中
* 设计了一个较为美观实用的UI界面

运行本项目需要额外安装的python库（在虚拟环境中安装）：

* scapy
* ttkthemes
* tkinter

### 1. 数据结构及算法介绍

* 本项目未自定义数据结构，使用的数据结构均为python原生
* 本项目亦无特殊算法，逻辑部分只是对scapy库的合理调用

### 2. 项目结构介绍

整个项目只包括一个代码文件。这个文件主要分为两部分：数据报处理部分、UI界面设计部分。

#### 2.1 数据报处理部分

实现的功能主要有：

* 捕获数据报并判断其类型，将分析后的结果存入全局变量以供展示
* 根据用户的过滤条件筛选出符合要求的数据报，然后展示
* 在用户点击查看某一数据报时，显示数据报内具体内容
* 将分片的IP数据报重组，并可以筛选出所有重组后的数据报

#### 2.2 UI界面设计部分

最终设计结果如下：

![image-20231201113320988](.\图图\image-20231201113320988.png)

### 3. 项目功能分析

#### 3.1 系统参数设定

在测试项目前，使用者需要查看本机网卡编号（例如我的是ens33）和MTU值。

```python
# 需要用户修改，为项目指定一个正确的网卡
iface = tk.StringVar()
iface.set('ens33')
# 根据自己主机的适配器信息进行修改
iface_option['values'] = ('ens33', 'wlan0')
```

```python
# 若数据报长度超过MTU，说明该数据报为重组后添加进全局变量。用户需要根据本机情况来修改
for packet in packets:
	if packet["Length"] > 1500:
...
```

#### 3.2 对于全局变量的解释

```python
keep_sniffing = True		# 是否处于工作模式标识
seen_packets = set()		# 用于记录已经捕获到的数据报，防止重复捕获造成冗余
packets = []				# 记录捕获到的数据报的信息
filter_packets = False		# 若当前展示已过滤的数据报，则置为True
is_filtered = False			# 若当前展示已重组的数据报，则置为True
fragments = {}				# 用于记录捕获到的分片
reassembled_packets = []	# 用于记录重组后的数据报
packet_id = 0				# 给每一个捕获到的数据报一个ID
```

#### 3.3 捕获数据报

```python
def packet_callback(packet):
    global ...									# 声明外部全局变量

    if not keep_sniffing:						# 若不处于工作模式，则直接退出
        return 
    packet_identifier = packet.summary()		# 生成数据报的摘要来过滤掉重复的数据报
    if packet_identifier not in seen_packets:	# 生成描述数据报的相关信息
        packet_dict = {}
        packet_dict["Packet Identifier"] = packet_identifier
        packet_dict["Timestamp"] = packet.time
        packet_dict["Length"] = len(packet)
        if packet.haslayer(Raw):
            packet_dict["Load"] = binascii.hexlify(packet.load).decode()	# 将负载部分转换为十六进制数
        else:
            packet_dict["Load"] = None
        # 存储信息的局部变量   
        source_ip = ''
        destination_ip = ''
        protocol = ''
        function = packet_identifier
        source_port = None
        destination_port = None
		# 分析数据报内容
        if packet.haslayer(Ether):
            ...
        if packet.haslayer(ARP):
            ...         
        elif packet.haslayer(IPv6):
            ...
        elif packet.haslayer(IP):
            ...
            if packet.haslayer(ICMP):
                ...
            elif packet.haslayer(TCP):
                ...
            elif packet.haslayer(UDP):
                ...
            # 处理分片    
            ip_id = packet[IP].id
            ip_frag = packet[IP].frag
            if packet[IP].flags.DF == False:        			# DF = False时才分片
                if ip_id not in fragments:
                    fragments[ip_id] = {}
                fragments[ip_id][ip_frag] = packet[IP].payload	# 将标识字段相同的分片进行存储
        # 将收集到的信息存储起来        
        packet_id += 1
        packet_dict["ID"] = packet_id
        packet_dict["Source IP"] = source_ip
        packet_dict["Destination IP"] = destination_ip
        packet_dict["Protocol"] = protocol
        packet_dict["Function"] = function
        packet_dict["Source Port"] = source_port
        packet_dict["Destination Port"] = destination_port
        packet_dict["IP ID"] = ip_id  # 将IP ID添加到数据包字典中
        packet_dict["IP DF flag"] = packet[IP].flags.DF if packet.haslayer(IP) else None
        packet_dict["IP MF flag"] = packet[IP].flags.MF if packet.haslayer(IP) else None
		# 将该数据报添加到全局变量
        packets.append(packet_dict)
		# 将该数据报标记为已收到
        seen_packets.add(packet_identifier)
```

#### 3.4 过滤数据报

```python
def toggle_filter():
    global ... 									# 声明全局变量
    filter_packets = not filter_packets			# 修改标记

    # 清空 Treeview，即将当前展示的数据报信息清空
    for i in tree.get_children():
        tree.delete(i)

    # 重新处理已经接收到的数据包
    for packet in packets:
        source_ip = packet["Source IP"]
        destination_ip = packet["Destination IP"]
        protocol = packet["Protocol"]
		# 根据过滤条件筛选
        if filter_packets:
            if source_ip_filter.get() and source_ip != source_ip_filter.get():
                continue
            if destination_ip_filter.get() and destination_ip != destination_ip_filter.get():
                continue
            if protocol_filter.get() != 'All' and protocol != protocol_filter.get():
            	continue

        # 将符合条件的数据包添加到 Treeview
        tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], source_ip, destination_ip, packet["Protocol"], packet["Function"]))
```

#### 3.5 展示数据报细节

```python
def show_packet(event):
    global ...						# 声明全局变量
    curselection = tree.focus()		# 获取当前选中的项
    if curselection:  				# 如果有选中的项
        packet_text.delete(1.0, tk.END)
        selected_id = tree.item(curselection)['values'][0]  # 获取选中项的 'ID' 列的值
        # 使用 selected_id 查找 packets 列表中的相应数据包
        packet = next((p for p in packets if p["ID"] == selected_id), None)
        if packet is not None:
        timestamp = packet["Timestamp"]			# 将Unix时间戳转换为可读的日期和时间
        if isinstance(timestamp, str):        	# 检查timestamp的类型
            # 如果timestamp是字符串，那么我们假设它是一个日期时间字符串
            dt_object = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
        else:
            # 否则，我们假设timestamp是一个Unix时间戳，并对其进行格式化
            dt_object = datetime.datetime.fromtimestamp(int(timestamp))
            formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S")
            packet["Timestamp"] = formatted_time
			packet_text.insert(tk.END, json.dumps(packet, indent=4))

    else:  # 如果没有选中的项
        packet_text.delete(1.0, tk.END)
        packet_text.insert(tk.END, "No packet selected.")
```

#### 3.6 过滤重组后的数据报

```python
def filter_by_length():
    global is_filtered
    # 清空 Treeview
    for i in tree.get_children():
        tree.delete(i)
        
    if is_filtered:
        # 如果当前是过滤状态，那么显示所有数据包
        for packet in packets:
            tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], packet["Source IP"], packet["Destination IP"], packet["Protocol"], packet["Function"]))
    else:
        for packet in packets:
            if packet["Length"] > 1500:				# 根据MTU判断哪些数据报是重组后的
                tree.insert('', 'end', values=(packet["ID"], packet["Timestamp"], packet["Source IP"], 									packet["Destination IP"], packet["Protocol"], packet["Function"]))

    # 切换 is_filtered 的值
    is_filtered = not is_filtered
```

#### 3.7 UI界面设计

```python
root = ThemedTk(theme="arc")					# 创建一个基础窗口
root.title("Packet Sniffer")					# 窗口标题
root.geometry("1400x900")						# 默认的窗口大小
my_font = font.Font(family="Arial", size=14)	# 设置个性化字体
```

```python
# 设置行和列的权重，使得它们可以随窗口尺寸变化
for i in range(6):
    root.grid_rowconfigure(i, weight=1, minsize=50)
for i in range(2):
    root.grid_columnconfigure(i, weight=1, minsize=100)
```

其他组件的设计方法为：

* 创建一个Frame，设置该Frame在root窗口上的位置
* 将组件注册到Frame内以完成布局

所有组件的排布逻辑都是类似的，在此不一一赘述

### 4. 项目操作说明

#### 4.1 开始捕获数据报

在命令行执行代码文件（虚拟机下需要使用管理员权限）

```python
sudo python3 sniffer.py
```

点击窗口中的Start sniffering按钮，捕获到的数据报便会显示出来。点击某一条数据报信息，下面的文本框中便会显示细节.

点击按钮后程序调用$start\_sniffering()$函数，创建新线程开始抓包

```python
def start_sniffing():
    global sniff_thread
    global keep_sniffing
    keep_sniffing = True
    sniff_thread = Thread(target=sniff, kwargs={'iface': iface.get(), 'prn': packet_callback, 'store': 0}, 														daemon=True)
    sniff_thread.start()
```

效果图如下：

![image-20231201124358338](.\图图\image-20231201124358338.png)

其中细节部分包括：数据报的摘要、时间戳、数据报长度、负载、IP头的标识、源IP、目的IP、DF标志等等

值得注意的是负载部分的值单独查看是没有意义的，我在设计时只令其按照十六进制数显示，若要分析可以将其复制出去

<font color="red">注意：</font>**有时在显示捕获的数据报时ID会出现重复和跳过某些值的问题，此时点击一下Filter即可**

#### 4.2 根据需求过滤数据报

在输入框输入目的IP和源IP，并选择感兴趣的协议类型（默认为全部协议），点击Filter按钮进行筛选

* 只根据源IP进行过滤

![image-20231201124857843](.\图图\image-20231201124857843.png)

* 根据协议类型进行过滤

![image-20231201125033518](.\图图\image-20231201125033518.png)

#### 4.3 显示重组后数据报

点击Show combined pieces显示重组后的数据报

![image-20231201142444776](.\图图\image-20231201142444776.png)

![image-20231201142620781](.\图图\image-20231201142620781.png)

这里再次进行说明，本项目判断数据报是否已重组的依据是数据报的长度和DF字段的值。对于负载部分的具体数据信息不做处理。

#### 4.4 保存数据报信息

在文件名输入框内输入文件名后，点击Save按钮即可将捕获的数据报信息保存。**建议将文件保存为json格式，这样可读性更强**

```python
def save_packets():
    global packets
    global filename
    if filename.get() == "":
        messagebox.showerror("Error", "Please enter a filename.")   	# 文本框空异常检测
        return
    with open(filename.get(), "w") as log_file:
        for packet in packets:
            json.dump(packet, log_file, indent=4)						# 格式化存储保证可读性
            log_file.write("\n")
    packets = []
```

![image-20231201142720893](.\图图\image-20231201142720893.png)

![image-20231201142950483](.\图图\image-20231201142950483.png)

![image-20231201142833857](.\图图\image-20231201142833857.png)

### 5. 实例演示

#### 5.1 进行ping请求

```python
ping www.bilibili.com
```

1. 向DNS服务器发送域名解析请求

![image-20231201150853968](.\图图\image-20231201150853968.png)

![image-20231201145959115](.\图图\image-20231201145959115.png)

2. DNS服务器回复请求

![image-20231201150909537](.\图图\image-20231201150909537.png)

![image-20231201150456283](.\图图\image-20231201150456283.png)

3. 向解析出的IP发送ICMP报文

![image-20231201150530914](.\图图\image-20231201150530914.png)

![image-20231201150544589](.\图图\image-20231201150544589.png)

4. 收到ICMP回复报文

![image-20231201150820408](.\图图\image-20231201150820408.png)

![image-20231201150833065](.\图图\image-20231201150833065.png)

#### 5.2 访问网站（https://pypi.tuna.tsinghua.edu.cn/simple/）

1. 解析DNS

![image-20231201151851073](.\图图\image-20231201151851073.png)

![image-20231201151903042](.\图图\image-20231201151903042.png)

![image-20231201151918484](.\图图\image-20231201151918484.png)

2. 进行三次握手

（1）客户端发送连接申请

![image-20231201151955981](.\图图\image-20231201151955981.png)

（2）服务器同意连接

![image-20231201152023021](.\图图\image-20231201152023021.png)

（3）客户端发送确认

![image-20231201152047565](.\图图\image-20231201152047565.png)

3. 传输一些数据

![image-20231201152116342](.\图图\image-20231201152116342.png)

![image-20231201152146279](.\图图\image-20231201152146279.png)

#### 5.3 播放视频（www.bilibili.com）

1. 解析DNS

![image-20231201163312535](.\图图\image-20231201163312535.png)

这里解析了多个域名，可能是因为在播放视频时涉及不止一个服务器提供服务

2. 第一次握手

![image-20231201163416720](.\图图\image-20231201163416720.png)

3. 第二次握手

![image-20231201163521338](.\图图\image-20231201163521338.png)

4. 第三次握手

![image-20231201163544346](.\图图\image-20231201163544346.png)

5. 连接建立后开始传输数据

![image-20231201163622363](.\图图\image-20231201163622363.png)

### 6. 遇到的问题及解决方法

#### 6.1 进行功能切换时逻辑混乱

由于项目中涉及到根据条件过滤数据报、过滤重组后数据报等功能，因此在UI界面上点击某些按钮后会发生存储数据报信息的数据结构异常、数据报展示出错等问题。

解决方法只能是多次调试，慢慢设计

#### 6.2 UI界面设计

在最初设计UI界面的时候，由于对界面设计的代码不是很熟悉，总是出现组件“漂移”、“错位”、“重叠”等问题。虽然最终界面设计的也不是很完美，但也是我投入莫大精力后得到的

### 7. 体会与建议

#### 7.1 体会

在初次看到大作业的5个可选题目时，我对这次的大作业是抱着一种畏难的情绪的。

但是在真正开始后，我发现只要对课内知识有一定的掌握，再广泛的搜罗一番资料，完成这个大作业也不是很难。在这个过程中我不仅对所学内容有了更深刻的了解，也学会了如何利用python丰富的库来设计程序的UI界面，这对我之后的学习探索有着极大的意义。

当然我最大的收获还是自信，这些看似难度颇高的任务在用心钻研、逐步分解后也没有看上去那么唬人，只要肯花时间就一定可以完成。

#### 7.2 建议

可以对每个项目要用到的库进行一些简单的介绍，这样同学们在选题的时候可以对项目的实现方式有着更加直观的认识