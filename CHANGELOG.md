# 更新说明 / Changelog

## 未发布 / Unreleased

- 新增可选的 X83C Plus Life 本地电源控制实验：默认关闭，需要设备级 accessKey 和 accessToken。**尚未真机验证，很可能无法使用**；不提供其他 Life 型号的控制。失败或写入后无法确认时应检查设备状态。
- Life 设备可通过只读发现添加局域网连接状态；发现不代表已经取得控制授权。
- F072 接收路径兼容 G45 用户报告的 `0x02` 状态帧；其他 F072 型号仍缺少对应真机证据。

- Add opt-in experimental X83C Plus Life local power control. It requires device-specific accessKey and accessToken, has **not been tested on Life hardware and is likely not to work**, and does not provide control for other Life models. Check the device if a write cannot be confirmed.
- Discover Life devices for read-only local connection status; discovery does not establish control authorization.
- Accept F072 `0x02` state frames reported by a G45 user; other F072 models lack corresponding hardware evidence.
