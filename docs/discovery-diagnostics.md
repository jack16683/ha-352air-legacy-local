# 发现失败诊断 / Discovery diagnostics

适用于添加设备时提示“没有收到设备的有效响应”的情况。诊断补丁不改变
探测报文、校验规则、主动探测 4 秒或被动等待 42 秒的默认时限，不发送控制报文。

## 复测

1. 安装包含诊断补丁的版本并重启 Home Assistant；只更改日志等级不会加载新代码。
2. 在 `configuration.yaml` 合并以下配置（不要重复顶层 `logger:`），重启 HA：

   ```yaml
   logger:
     logs:
       custom_components.352air_legacy_local: debug
   ```

3. 单次手动添加 X83C Plus，填入其当前 IP/MAC，选择 X83C Plus，等待成功或报错。
   不要同时发起多次添加；本补丁不记录设备标识来关联并发尝试。
4. 从完整 `home-assistant.log` 或容器日志中取出本次 `Discovery diagnostics start`
   到最终 `outcome=...` 的日志，以及相邻 config_flow / UDP 日志。
   HA 界面若只显示警告/错误，请下载完整日志。若仍没有 start 行，先确认加载了补丁、
   重启过 HA，且 logger 名称完全一致，不能据此推断设备没有回应。
5. 如方便，再单独对正常 X83C 做一次同样复测，分别标注型号。
   不必删除已有条目；同一设备可能在验证完成后提示已配置。

新增日志只记录计数、固定原因标签、协议族编号和等待时限，不记录 IP、MAC、
鉴权码或原始报文。分享完整日志前仍需检查其他组件输出中的敏感信息。
无需公开抓包、token 或鉴权码。

## 如何解释

| 字段 | 含义 |
| --- | --- |
| `probes` / `probes_sent` | 已交给 UDP endpoint 的探测报文数，不保证网络送达 |
| `received` | 本次订阅在完成前收到的总数据报数 |
| `target_received` | 来自填写的目标 IP 的数据报数，尚未表示身份/端口校验通过 |
| `other_received` | 其他来源 IP 的数据报数，可能来自已接入的 X83C |
| `phase=active/passive/bind` | 主动探测、被动等待、endpoint 获取失败 |
| `outcome=active_timeout` | 主动阶段结束时的中间快照，可能继续被动等待并成功 |
| `outcome=timeout/success/endpoint_error/interrupted` | 最终超时、成功、endpoint 错误、取消或异常退出 |
| `accepted=discovery_reply/passive_state` | 成功来自发现响应或已验证的状态帧；与到达阶段相互独立 |
| `discovery_rejections` | 目标 IP 数据报在发现响应解析器中的首个拒绝原因计数 |
| `state_rejections` | 发现解析未通过后，目标 IP 数据报在被动状态解析器中的首个拒绝原因计数 |

两个解析器的计数不能相加当作报文总数。同一报文可各记一次拒绝；正常状态报文
也会先产生 `discovery_operation`，随后被状态解析器接受。计数为累计值，
主动超时快照与最终汇总也不能相加。其他来源只计数，不收集拒绝原因。

- `target_received=0`：这次 HA 订阅未观察到来自目标 IP 的数据报，不能证明设备
  没有发包，也不能单凭这一项断定固件不支持本地控制。
- `outer_too_short/outer_header/outer_declared_length/outer_length_mismatch/outer_identity`：
  外层格式校验未通过。
- `source_port_or_shape/source_mismatch`：响应来源端口/地址不符合当前规则。
- `discovery_operation/discovery_payload`：不是当前支持的发现响应类型/结构。
- `embedded_mac_mismatch/target_mac_mismatch/advertised_address_mismatch/sequence_mismatch`：
  身份、声明地址或序列号未通过校验；不会输出实际值。
- `state_operation/state_wire_type/state_payload_layout/state_crc`：
  被动状态操作码、协议族、结构或 CRC 未通过校验。

## X83C Plus 的证据边界

仓库 APK 静态研究将 X83C Plus 映射到 type 2。33/65 字节、`02 5A A1`
状态结构有 X83C 实机证据，但没有 `1.6.3_EMC3080P` 固件的实机验证。
云端集成通过阿里云 IoT 连接成功，不证明设备开放相同的本地 UDP 协议。
本补丁提供进一步区分路径的证据，不声称修复了 X83C Plus 兼容性。

## 开发验证

```bash
python -m unittest discover -s tests -v
python -m ruff check custom_components tools tests
python -m ruff format --check custom_components tools tests
```

测试使用合成报文与模拟 endpoint，仅替代 HA Platform 枚举以便独立运行。
它们验证实际发现解析、重试、阶段切换、释放 endpoint 和日志脱敏；不等同于
Home Assistant 完整配置流程测试或 X83C Plus 实机验证。
