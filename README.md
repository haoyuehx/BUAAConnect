# BUAAConnect

面向北京航空航天大学网络环境的第三方 Go 命令行 VPN 客户端。

本程序基于 [zju-connect](https://github.com/Mythologyli/zju-connect) 开发，针对北航网络环境进行适配。感谢上游维护者、贡献者及原始项目 [EasierConnect](https://github.com/lyc8503/EasierConnect) 的作者 [lyc8503](https://github.com/lyc8503)。

> **当前状态：项目初始化。** 已导入上游实现并提供 ACT VPN 配置示例，尚未完成 BUAAConnect 的 ACT 登录和数据转发实机验证，暂未发布经过验证的安装包。

## 免责声明

BUAAConnect 是个人维护的非官方项目，与北京航空航天大学、深信服及上游项目维护者无隶属或背书关系。相关名称和商标属于各自权利人。

本程序按现状提供，不对适用性、正确性、可靠性或持续可用性作保证。使用者应遵守学校网络管理规定及适用法律，仅使用本人获授权的账号访问获授权的资源。本程序不用于绕过身份认证、访问控制、流量审计或安全检查。具体许可和责任限制以仓库中的 [LICENSE](LICENSE) 为准。

## 适配范围

| 入口 | 当前状态 |
| --- | --- |
| ACT VPN：`vpn.act.buaa.edu.cn:8443` | 已提供初始配置，待实机验证 |
| 学校其他 VPN 入口 | 尚未验证，暂不宣称支持 |

上游具有 EasyConnect / aTrust、SOCKS5 / HTTP 代理、端口转发及 TUN 等实现。这些是继承的能力，不代表已在北航所有入口完成验证。

本项目当前以命令行为入口，不提供 BUAAConnect 图形客户端。

## 从源码构建

需安装 Git 和满足 [go.mod](go.mod) 要求的 Go 工具链（当前为 Go 1.25.6）。

```bash
git clone https://github.com/haoyuehx/BUAAConnect.git
cd BUAAConnect
go build -o buaaconnect .
./buaaconnect -help
```

当前仍保留上游 Go module 路径、部分内部命名及参数前缀，以减少初始改动和方便同步；可执行文件通过构建命令命名为 `buaaconnect`。

## ACT VPN 初次连接

先断开 EasyConnect，避免同时登录干扰验证。复制示例配置：

```bash
cp config.act.toml.example config.act.toml
chmod 600 config.act.toml
```

在 zsh 中运行以下命令，替换 VPN 用户名。密码从终端隐藏输入，通过上游支持的环境变量提供，不直接写入命令历史：

```zsh
read -rs 'ZJU_CONNECT_PASSWORD?ACT VPN 密码：'
echo
export ZJU_CONNECT_PASSWORD
./buaaconnect -config config.act.toml -username 'YOUR_ACT_USERNAME'
unset ZJU_CONNECT_PASSWORD
```

如出现验证码或协议错误，以实际输出为准；当前不能保证该入口的所有认证方式均兼容。前台运行时，按 Ctrl+C 断开。

默认代理仅监听本机：

| 协议 | 地址 |
| --- | --- |
| SOCKS5 | `127.0.0.1:11080` |
| HTTP | `127.0.0.1:11081` |

普通 SSH 不会自动使用这些代理。如只需要访问一台 SSH 服务器，可以配置以下端口转发。

## SSH 端口转发

编辑 `config.act.toml`，将其中的 `port_forwarding = []` 替换为：

```toml
port_forwarding = [
  { network_type = "tcp", bind_address = "127.0.0.1:2222", remote_address = "YOUR_SERVER_IP:22" }
]
```

将 `YOUR_SERVER_IP` 换成本人有权访问的服务器地址。重启客户端并确认登录成功后，在另一终端执行：

```bash
ssh -p 2222 YOUR_SERVER_USERNAME@127.0.0.1
```

服务器账号与 VPN 账号可能不同。首次连接应核对服务器 SSH 主机指纹。

示例配置的 `proxy_all = true` 表示将进入本客户端代理或转发的目标交给 VPN，适用于验证服务端资源列表不完整的情况；它不会自动接管电脑全部流量，也不会增加服务端授予的访问权限。

## 常见问题

- **VPN 登录成功，服务器仍不可达：** 检查资源权限、目标服务、转发配置和服务端资源列表。登录成功不等于所有内网地址均可访问。
- **与 Clash 共用：** 本示例使用独立的本机监听端口。若开启其他工具的 TUN 模式，仍需检查 VPN 入口的直连规则和系统路由。
- **端口已占用：** 更改 `socks_bind`、`http_bind` 或端口转发的本机端口。
- **提交问题：** 请附操作系统、构建版本和脱敏后的错误输出；不要提交密码、验证码、Cookie、会话标识或私钥。

## 后续工作

- 验证 ACT 登录、SSH 转发、退出和网络中断行为。
- 完善北航连接配置及连接诊断。
- 增加便捷的凭据输入和后台运行管理。
- 按实际测试结果扩展其他北航 VPN 入口。

以上是开发计划，不表示功能已完成。

## 来源与许可证

本项目使用 **AGPL-3.0** 许可证，保留上游许可证及源文件中的版权声明。修改、分发及通过网络提供服务时，请遵守相应许可要求。致谢不能替代许可证义务。

- 直接上游：[Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
- 原始项目：[lyc8503/EasierConnect](https://github.com/lyc8503/EasierConnect)
- 源码来源记录：[UPSTREAM.md](UPSTREAM.md)
