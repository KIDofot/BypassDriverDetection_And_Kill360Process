# BypassDriverDetection_And_Kill360Process

**环境：Win7 7600 x86**

**360版本：11.4.0.2002**

**目标1：绕过360加载驱动检测。**

**目标2：实现结束360关键进程。**

# 一、Ring3绕过360加载驱动检测
## 1、Statement
## 2、Extend

# 二、实现结束360关键进程
## 1、MiIsAddressValidEx

## 2.1、ZeroProcessMemory
## 2.2、杀掉进程其它实现：

## 3、分析Win2000源码
### 3.1、MmIsAddressValid
### 3.2、ProbeForRead()
### 3.3、ProbeForWrite()
### 3.4、总结：

# 三、实现代码：
## 1、绕过检测代码
## 2、结束进程代码
