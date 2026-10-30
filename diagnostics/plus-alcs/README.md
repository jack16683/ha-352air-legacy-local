# X83C Plus 授权测试工具

`0.1.0-test1`，独立测试工具，不是 HA 集成更新。先云端登录取得目标设备凭据，再验证
本地认证和加密读取；只有显式运行 `install` 才执行一次本地授权 setup。
尚未使用真实账号、Plus 或真实群晖/HA 容器验证，不能据此认定已支持本地控制。

## 在群晖终端运行

从 Issue #2 的固定版本链接下载源码包，进入其中的 `diagnostics/plus-alcs`。
在**群晖宿主机 SSH 交互终端**执行，不要放在 OpenClaw 代执行任务中。
把 `PLUS_IP` 替换为路由器里确认的 Plus 当前地址：

```sh
sh run.sh baseline PLUS_IP --observe --report baseline-report.json
```

工具依次隐藏询问：独立的本地恢复资料密码（首次两次确认）、352 账号、352 密码。
**不需要提供或安装 App，不需要手动提取 token。** 工具直接请求官方服务登录、
精确匹配该账号已有的目标设备、取得 accessKey/accessToken，再在本机使用它们。
352 密码不能与恢复资料密码相同，恢复资料密码至少 12 字符。

首次运行时，工具自动下载约 158 MiB 的固定版本公开分发文件，校验完整 SHA-256，
只读取应用级签名配置；不安装、不运行 App，也不需要你提供 APK。下载只访问
应用宝分发地址及其限定 HTTPS CDN，临时文件随后删除。该步骤没有账号密码，
不接触设备；校验失败就停止，不从其他来源猜测配置。

352 登录与后续会话交换只请求官方 352/阿里 HTTPS 接口，校验证书，不跟随 API
重定向，不使用代理环境变量。不会经过维护者服务器，也没有遥测或自动报告回传。
账号密码不放在命令行、环境变量、文件、日志或报告中，不会发给维护者。

入口优先使用本机已有 Python 3.8+ 和 cryptography；缺项时尝试**本机已有**且使用
host 网络的 HA 容器。不会安装软件、创建容器、重启 HA 或修改网络。
多个符合条件的容器时，可加 `--ha-container 容器名`，之后各命令保持相同选择。
依赖或权限不足会给出错误码，不要求先修改系统。Python 3.8 目前只验证了运行源码
语法兼容，本地完整测试在 Python 3.12.14 上完成。

读成功后，`--observe` 提示你在 45 秒内按机身电源切换一次、保持约 5 秒、再恢复
原始状态。没有提示就不操作。**工具从不发送电源写入**；读失败或没有确认恢复，
请亲自检查机器的电源状态。首次只运行这一条基线命令，分享脱敏报告即可。

## 准备恢复计划后再 setup

只有目标为 X83C Plus / `1.6.3_EMC3080P`、云端在线且属性新鲜、云端与本地读数
一致、已有本地认证和读取正常时，才允许安装。基线失败时不要继续。
新云登录可能让现有 App/云集成需要重新认证；先处理并记录这类变化。

**accessKey/accessToken 不是完整的旧服务端密钥备份，不能保证原样回滚。**
安装会改变本地 ALCS 授权，可能影响旧凭据。需要以下任一恢复计划，内容只留本机：

- 已知原本地服务端 prefix/secret：复制 `examples/recovery-known-key.example.json`，
  在本机编辑器中填入。工具先实际认证和读取，验证不通过就不安装。不要填云密码或
  accessToken。
- 所有者手动恢复：复制 `examples/recovery-manual.example.json`，仅在你实际具备
  其中操作的条件并理解影响后，才把 `owner_can_execute` 改为 `true`。
  `official_app_repair` 指你自己已确认的官方 App 恢复办法，
  `factory_reset_and_rebind` 指你有条件自行恢复出厂并重新绑定。
  工具未验证这两种办法的实际效果，也不会替你执行重置或绑定。

例如先复制手动计划模板（默认 false，直接运行不会通过）：

```sh
cp examples/recovery-manual.example.json recovery-plan.private.json
chmod 600 recovery-plan.private.json
```

没有合适恢复条件就停在基线。“重新登录试试”不算已确认的恢复方案。
准备并在本机编辑好恢复计划后，单独执行：

```sh
sh run.sh install PLUS_IP --observe --recovery-file recovery-plan.private.json --report install-report.json
```

该命令重新登录并复核云端和旧 LAN 基线，先加密保存新密钥、已有设备访问凭据和
恢复计划，持久保存尝试记录之后，只发送**一条**加密 setup 数据报。
不改 Wi-Fi、设备 deviceSecret 或绑定，不自动重试安装。返回 200 也不能说明成功，
之后用新密钥、新 socket、新挑战值认证和读取，再检查旧本地凭据和原云会话状态。
安装后的状态观察也需要本人确认改变并恢复；未确认会标记 attention 并返回非零。

若回包丢失或进程中断，保留所有恢复资料，先运行 verify，**不要删除恢复目录来
重复 install**。同一资料一旦记录安装尝试，baseline/install 都不能再覆盖它。

## 后续验证与恢复命令

verify 默认不再登录云端，只用本机保存的新旧设备凭据重新认证、读取，不写设备：

```sh
sh run.sh verify PLUS_IP --report verify-report.json
```

由你自己明确完成一次真正的设备/模组重启后，可单独复查持久性；机身电源 OFF
不等于模组重启，工具不会自动重启设备：

```sh
sh run.sh verify PLUS_IP --after-reboot --report reboot-report.json
```

DHCP 地址变化时使用新 IP；仍严格核对同一设备身份和凭据证明。报告会明确重启
事实由运行者声明，不把这次读取当作所有功能都已验证。

**只有恢复计划里有已验证过的旧 prefix/secret** 时，才能尝试工具恢复访问：

```sh
sh run.sh restore PLUS_IP --report restore-report.json
```

恢复同样只写一次，再用旧密钥全新认证和读取，并检查测试密钥是否仍可访问。
这不保证删除测试密钥、恢复全部授权表或落盘；`exact_configuration_restored=false`。
只有手动计划时，返回 `MANUAL_RECOVERY_REQUIRED`，工具不写入、不重置；
需按你自己已确认的方案恢复，未知旧密钥不能由工具找回。

verify/restore 默认不登录云端。确需额外登录官方云端复查时，加 `--cloud-check`，
此时才再次询问账号密码，也可能影响旧云登录。云属性陈旧或读数不匹配会标记
`cloud_recheck_attention=true`。

## 保留资料，只分享脱敏 JSON

- 恢复资料在本机的 `plus-private-state/`；HA 容器模式在
  `/config/plus-private-state/`。独立密码加密，目录 700、文件 600。
- 应用级签名配置在 `plus-cloud-config/`，容器模式为 `/config/plus-cloud-config/`，
  同样限制权限。没有打包在公开源码中。不要上传它或恢复计划原件。
- **只分享 `--report` 生成的 JSON**。不含账号密码、IP、MAC、设备名或 token。
  不要上传整个目录、加密恢复文件、签名配置、原始报文或终端输入截图。
- 报告只新建不覆盖。文件名已存在就换名；账号密码不能写进命令或参数。
- 异常退出后的锁可用 `sh run.sh unlock --report unlock-report.json` 清理，但只允许
  清理已退出进程的锁；不会清除尝试记录。清锁后先 verify，不重试 setup。

支持已对照的 ALCS opt 1/5/7，其他协商、Block2、未知关键选项会停止。
`setup_outcome_unconfirmed` 表示安装效果未知；
`new_key_read_verified_cloud_attention` 表示新本地读取正常但云端需要处理。
这两种情况都应保留资料和脱敏报告，不自动重试写入。

## 开发验证

97 项本地测试已通过，使用合成账号、模拟云端及本机 UDP 模拟设备；真实登录风控、
实际 Plus 授权优先级、落盘及恢复效果仍需实机验证。测试不会请求真实账号登录。

开发测试需 Python 3.12+ 和 cryptography；Ruff 配置区分运行源码与开发测试：

```sh
python3 -m unittest discover -s tests -v
```

这是独立工具测试，不修改 HA 集成，也不代表正式版本已支持 Plus 本地控制。
