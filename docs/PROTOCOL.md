# 协议与实现说明（M1）

本文只记录 M1 使用的只读流程，凭据使用占位符。

## 1. 两个管理面

| 端口 | 服务 | 认证 |
|---|---|---|
| 80 | LuCI / uhttpd | `sysauth` Cookie，普通用户 `useradmin` |
| 8080 | ty_httpd / 装维后台 | `telecomadmin` + TA 口令，按来源 IP 授权 |

8080 不是 LuCI，普通用户不能直接访问其管理页。

## 2. LuCI 登录

```http
GET /cgi-bin/luci
POST /cgi-bin/luci
Content-Type: application/x-www-form-urlencoded

username=useradmin&psd=<password>
```

成功：`302`，`Set-Cookie: sysauth=<32 hex>; path=/cgi-bin/luci/`。

失败：`200` 登录页，页面含“密码错误”。

## 3. 读取宽带账号

```http
GET /cgi-bin/luci/admin/settings/gwinfo?get=all
Cookie: sysauth=<...>
```

关键字段：

```json
{
  "ProductCls": "TGCT-526G",
  "ProductSN": "F01628-...",
  "SWVer": "V1.0.526G1V1",
  "WANIP": "172.20.x.x",
  "wanAcnt": "0755****@163.gd"
}
```

## 4. 默认 TA 口令检测

```http
POST /cgi-bin/luci
username=telecomadmin&psd=<ta_password>
```

如果 TA 口令有效，登录模板会输出自动跳转脚本：

```html
<form method="post" id="argform">
  <input type="hidden" name="username" value="telecomadmin" />
  <input type="hidden" name="psd" value="<ta_password>" />
</form>
<script>
  document.getElementById("argform").action = "http://host:8080/login.cgi";
  document.getElementById("psd").value = "<ta_password>";
  document.getElementById("argform").submit();
</script>
```

M1 用 `getElementById("psd").value == ta_password` 作为成功判据。页面同时可能出现
“密码错误”文案，这是模板分支的干扰，不能作为唯一判据。

## 5. 8080 登录

模板中的自动跳转使用 **明文 `psd`**：

```http
POST http://host:8080/login.cgi
username=telecomadmin&psd=<ta_password>
```

成功：`<script>parent.location='http://host:8080/main.html'</script>`。

8080 使用来源 IP 授权，不一定需要 Cookie。连续 3 次失败会返回：

```text
您重试错误用户名或密码超过三次，系统将禁止登录1分钟
```

M1 只尝试一次，遇到锁定立即停止，不继续爆破。

## 6. WAN 页面与密码解码

```http
GET http://host:8080/NN_WAN.html
```

页面内嵌：

```javascript
var WanConnStr = "记录1}记录2}记录3";
```

每条记录以 `|` 分隔：

| 索引 | 含义 |
|---|---|
| 0 | 连接名，例如 `3_INTERNET_R_VID_41` |
| 6 | VLAN |
| 8 | MTU |
| 9 | 宽带账号 |
| 10 | 宽带密码（Base64） |
| 14 | 接口名，例如 `ppp1.3` |

页面自身用 `$.base64.atob(wanConnParam[9], true)` 解码密码，因此 M1 做同样的
Base64 解码。Base64 不是加密。

## 7. 只读边界

M1 只发送上述 GET/POST：

- 不调用 `save`/`apply`/`reboot`/`restore`；
- 不访问 FTP、telnet、远程下载；
- 不写 `/etc`、`/data` 或 USB 存储；
- 日志对密码做长度提示，不打印明文。

## 8. 失败与限速

| 现象 | 处理 |
|---|---|
| LuCI 登录失败 | 停止，提示检查普通账号 |
| 默认 TA 不可用 | 停止，不爆破 |
| 8080 锁定 | 停止，提示等待 60 秒 |
| WAN 页面无 `WanConnStr` | 停止，记录错误 |
| 密码为空 | 保留账号，标注部分完成 |
