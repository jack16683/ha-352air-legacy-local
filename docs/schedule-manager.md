# 352 本机循环定时管理器

这是一个只使用 Python 标准库的独立工具，用来读取或清除老 352 设备
内部保存的循环开关机时间。它只访问局域网 UDP 11530，不登录或连接
352 云服务。

旧 App 创建的定时可能保存在净化器 MCU 内，即使 App 已无法登录也会
继续执行。建议在接入 Home Assistant 前先查询并清除不再需要的定时，
之后统一由 HA 自动化管理。

## 系统要求

- Windows、Linux 或 macOS
- Python 3.10 或更新版本
- 电脑和设备之间可以双向访问 UDP 11530

## 交互模式

```bash
cd tools
python3 352air_schedule_manager.py
```

直接回车使用中文，输入 `2` 切换英语。工具支持自动扫描和手动输入
IP/MAC；选择设备后会立即查询四个定时槽。发生输入或网络错误时会返回
菜单，方便修正后重试。

星期输入示例：

```text
135       周一、周三、周五
1234567   每天
all       每天
```

时间使用四位 24 小时格式，例如 `0700`、`1930`。

## 命令行模式

查看完整参数：

```bash
python3 352air_schedule_manager.py --help
python3 352air_schedule_manager.py query --help
python3 352air_schedule_manager.py set --help
```

常用示例：

```bash
# 查询
python3 352air_schedule_manager.py query \
  --host 192.0.2.44 --mac 02:00:00:00:00:44 --model x83c

# 清除四个设备端循环定时槽
python3 352air_schedule_manager.py clear \
  --host 192.0.2.44 --mac 02:00:00:00:00:44 --model x83c
```

示例中的 IP 和 MAC 是文档保留地址与合成标识，不是真实设备。

## 扫描说明

不同系统的邻居表和防火墙行为不同。工具会尝试制造邻居流量、查询 352
厂商 MAC、发送定向只读探测，并在需要时监听设备状态广播。如果自动
扫描没有结果，选择手动方式输入设备 IP 和 MAC 通常更可靠；跨网段或
VPN 环境必须保证双向 UDP 可达。

## 支持范围

- X83/X83C/X83C Plus：协议族已确认；X83C 已实机验证。
- X50/X50S/X60/X70：APK 静态确认，实验性。
- G30/G45：APK 静态确认，实验性。
- M25：检测仪，没有净化器循环开关机协议证据，因此不支持。

清除前请先查看四个槽。设备端定时即使 HA 离线也会继续执行；HA 自动化
则依赖 HA 在触发时正常运行，避免同时保留两套互相冲突的计划。

---

## English quick start

Run `python3 352air_schedule_manager.py`, then enter `2` at the language prompt.
The tool queries the four device-side recurring schedule slots immediately
after a device is selected. It uses local UDP 11530 only and never connects to
the retired 352 cloud service. Use a manual IP/MAC when discovery cannot cross
a routed network, VPN, or restrictive host firewall.
