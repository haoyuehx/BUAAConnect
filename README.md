# BUAAConnect

面向北京航空航天大学网络环境的第三方 Go 命令行 VPN 客户端。

本程序基于 [zju-connect](https://github.com/Mythologyli/zju-connect) 开发，针对北航网络环境进行适配。感谢上游维护者、贡献者及原始项目 [EasierConnect](https://github.com/lyc8503/EasierConnect) 的作者 [lyc8503](https://github.com/lyc8503)。

## 免责声明

BUAAConnect 是个人维护的非官方项目，与北京航空航天大学、深信服及上游项目维护者无隶属或背书关系。相关名称和商标属于各自权利人。

本程序按现状提供，不对适用性、正确性、可靠性或持续可用性作保证。使用者应遵守学校网络管理规定及适用法律，仅使用本人获授权的账号访问获授权的资源。本程序不用于绕过身份认证、访问控制、流量审计或安全检查。具体许可和责任限制以仓库中的 [LICENSE](LICENSE) 为准。

## 功能状态说明（已实现 / 已验证 / 待实机验证）

| 模块 / 能力 | 状态 | 说明 |
| --- | --- | --- |
| CLI 子命令 (`connect` / `status` / `disconnect` / `doctor` / `version`) | **已实现并通过单测/本地验证** | 支持子命令及传统 flag 兼容模式 |
| 双 Profile 独立配置 (`--profile school` / `--profile act`) | **已实现并通过单测验证** | 学校 VPN (`vpn.buaa.edu.cn:443`) 与 ACT VPN (`vpn.act.buaa.edu.cn:8443`) 独立配置，默认禁用 ZJU 专属规则，绝不误连浙大 |
| 凭据安全与隐藏输入 | **已实现并通过单测验证** | 支持终端无回显读取密码 (`term.ReadPassword`)、`BUAA_CONNECT_PASSWORD` 环境变量、命令行明文 `--password` 警告、日志与状态文件凭据脱敏 |
| 后台运行 (`--daemon` / `-d`) 与进程归属保护 | **已实现并通过单测验证** | 前台完成密码读取后通过 stdin 管道启动后台子进程；Linux 下使用 `/proc/<pid>/stat` `starttime`（字段 22）+ basename 校验进程归属，防止过期 PID 误杀其他进程 |
| TUN 分流路由、`--extra-routes` 与归属回滚 | **已实现并通过 Mock 单测验证** | 默认创建 `buaa-school` / `buaa-act` 接口（不假定 `tun0` 归属本程序）；跟踪本进程新增路由，已有路由冲突 (`File exists`) 不误删；支持初始化失败与退出回滚；对路由及 `--extra-routes` 自动排除 VPN 服务端自身 IP 防回环，并拒绝 `< /8` 的过宽额外路由 |
| Linux 分流 DNS (`--system-dns auto\|resolvectl\|off`) | **已实现并通过 Mock 单测验证** | 通过 `resolvectl` 在 TUN 接口上配置客户端 VIP:53 与 `~buaa.edu.cn` 等校内域名分流，退出时 `resolvectl revert` |
| Underlay 物理网卡绑定与 Clash 共存诊断 (`doctor`) | **已实现并通过单测与本机运行验证** | Underlay 自动探测排除 `POINTTOPOINT` / `tun*` / `Meta` / `mihomo` / `clash*` 虚拟接口；`doctor` 自动识别 Clash 关闭、普通代理、TUN 三种状态并给出证据与建议 |
| 两个 VPN 入口网络可达性预检 | **已在当前环境观测可达** | `vpn.buaa.edu.cn:443` 与 `vpn.act.buaa.edu.cn:8443` 的 `/por/login_auth.csp` 握手响应已在当前环境预检可达 |
| 真实账号登录、原 IP SSH、原网址浏览器访问与断开恢复 | **待用户本地输入凭据实机验证** | 需使用个人授权账号与 `sudo` / `CAP_NET_ADMIN` 权限在本地终端执行验证（见下方最短验证步骤） |

## 适配范围

| 入口 | Profile 名 | 地址 | 默认 TUN 接口名 |
| --- | --- | --- | --- |
| 学校 VPN | `school` | `vpn.buaa.edu.cn:443` | `buaa-school` |
| ACT VPN | `act` | `vpn.act.buaa.edu.cn:8443` | `buaa-act` |

两个入口分别认证，账号密码相互独立。客户端仅负责 VPN 认证、TUN 隧道、分流路由和 DNS，不负责具体业务网站登录或 SSH 账户认证。首期支持择一连接，不要求同时连接两个入口。

## 从源码构建与测试

需安装 Git 和满足 [go.mod](go.mod) 要求的 Go 工具链（Go 1.25+）：

```bash
git clone https://github.com/haoyuehx/BUAAConnect.git
cd BUAAConnect
go test ./... -count=1
go build -o buaaconnect .
./buaaconnect version
```

### 权限说明（Linux TUN 模式）

主路径（TUN + 分流路由 + `resolvectl` DNS）需要 `CAP_NET_ADMIN` 权限及 `/dev/net/tun` 访问权限。可以：
1. 使用 `sudo ./buaaconnect connect ...` 运行；或
2. 为二进制赋予最小网络管理能力：
   ```bash
   sudo setcap cap_net_admin+eip ./buaaconnect
   ```
如果仅使用 SOCKS5 / HTTP 代理或端口转发（`--tun-mode=false`），则无需管理员权限。

## 快速开始与命令用法

### 1. 环境与 Clash 共存诊断 (`doctor`)

在连接前可运行 `doctor` 检查权限、`/dev/net/tun`、`resolvectl`、本地端口占用以及 Clash 共存状态：

```bash
./buaaconnect doctor
./buaaconnect doctor --profile school
./buaaconnect doctor --profile act
```

### 2. 连接学校 VPN (`school`)

**方式 A：直接通过 `--profile school` 连接（终端隐藏输入密码）**

```bash
# 前台运行（按 Ctrl+C 断开并自动清理 TUN、路由与 DNS）
sudo ./buaaconnect connect --profile school --username 'YOUR_BUAA_USERNAME'

# 或：前台隐藏输入密码，认证及隧道建立成功后自动转入后台运行
sudo ./buaaconnect connect --profile school --username 'YOUR_BUAA_USERNAME' --daemon
```

**方式 B：使用配置文件连接**

```bash
cp config.school.toml.example config.school.toml
chmod 600 config.school.toml
# 编辑 config.school.toml 填入 username（密码建议在连接时交互输入或通过环境变量 BUAA_CONNECT_PASSWORD 提供）
sudo ./buaaconnect connect --config config.school.toml
```

### 3. 连接 ACT VPN (`act`)

ACT 入口常常存在服务端下发资源列表不完整的情况，可通过 `--extra-routes`（或配置文件中的 `extra_routes`）显式将目标服务器 IP 或网段加入本机 TUN 路由与客户端转发白名单（注：额外路由仅改变本机入站转发，不增加服务端授予的账号权限）：

```bash
# 前台连接 ACT VPN，并添加目标服务器或网段路由
sudo ./buaaconnect connect --profile act --username 'YOUR_ACT_USERNAME' --extra-routes '10.212.0.0/16,192.168.1.100'

# 或后台运行
sudo ./buaaconnect connect --profile act --username 'YOUR_ACT_USERNAME' --extra-routes '10.212.0.0/16' --daemon
```

使用配置文件：

```bash
cp config.act.toml.example config.act.toml
chmod 600 config.act.toml
sudo ./buaaconnect connect --config config.act.toml
```

### 4. 查看状态 (`status`) 与连通性探测

```bash
# 查看进程、认证、TUN 接口、分配 IP、已添加路由和 DNS 状态
./buaaconnect status

# 可选：指定授权目标地址验证连通性（未指定 --probe 时不会伪造“所有资源可达”）
./buaaconnect status --probe 10.212.x.x:22
```

### 5. 断开连接 (`disconnect`)

```bash
# 校验进程归属后发送 SIGTERM 优雅退出，回滚本程序添加的路由、DNS 与 TUN 接口
sudo ./buaaconnect disconnect
```

## 可选模式：SOCKS5 / HTTP 代理与端口转发

当不启用 TUN 模式（`--tun-mode=false`）时，客户端默认在本地监听：
- SOCKS5：`127.0.0.1:11080`
- HTTP：`127.0.0.1:11081`

也可以通过 `--tcp-port-forwarding 127.0.0.1:2222-YOUR_SERVER_IP:22` 或配置文件中的 `port_forwarding` 配置端口转发。

## 与 Clash / 外部 TUN 共存说明

- **Clash 关闭或普通系统代理模式**：BUAAConnect 的 TUN 分流路由仅接管服务端下发网段及 `--extra-routes` 指定的校内目标，DNS 仅针对 `~buaa.edu.cn` 及服务端下发域名走 VPN，普通互联网流量不受影响。
- **Clash TUN 模式或其他 VPN (`tun0`) 开启时**：
  - BUAAConnect 自动探测底层接口时会排除 `tun*`、`utun*`、`Meta`、`mihomo`、`clash*` 等虚拟接口，避免把 VPN 隧道建立在 Clash TUN 之上导致回环；您也可以通过 `--bind-interface <物理网卡名，如 wlp4s0/eth0>` 显式指定物理网卡。
  - BUAAConnect 不会清空或覆盖用户的 Clash 规则、接口或已有路由（遇到已有同前缀路由时仅告警并跳过归属记录，退出时绝不误删）。
  - 若 Clash TUN 使用了全局 `ip rule` 策略路由或 `198.18.0.0/16` Fake-IP 劫持，运行 `./buaaconnect doctor` 会输出具体冲突证据与调整建议。

## 来源与许可证

本项目使用 **AGPL-3.0** 许可证，保留上游许可证及源文件中的版权声明。修改、分发及通过网络提供服务时，请遵守相应许可要求。

- 直接上游：[Mythologyli/zju-connect](https://github.com/Mythologyli/zju-connect)
- 原始项目：[lyc8503/EasierConnect](https://github.com/lyc8503/EasierConnect)
- 源码来源记录：[UPSTREAM.md](UPSTREAM.md)
