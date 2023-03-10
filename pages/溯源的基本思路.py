import streamlit as st

"""
# 溯源的基本思路

这只是基本的溯源思路和思考方式。

## 1.溯源目的

### 1.1 你想要溯源到什么东西

要有明确的溯源目标

### 1.2 当前条件下能用什么东西来溯源

身边可以利用的工具或者方法

## 2.溯源的结论

### 2.1 任何再完美的溯源都是有可能失败的，攻防本身就是技术储备的对抗。

### 2.2 社会工程学，yyds！

## 3.溯源的途径

### 3.1 电子设备

移动设备（手机等）和移不动设备（计算机等）

### 3.2 非电子设备

快递，书信，线下battle等

## 4.溯源的思考方式

攻击者的攻击方式大部分都是攻击计算机（买通防守方除外），所以最初接触到攻击者都是在网络上，那么就需要思考网络上存在的东西哪些是可以利用的：

### 4.1 技术手段

#### 4.1.1 ip（不可能是真的）：

节点的提供商-》有没有可能联系到客服-》客服有没有可能套出购买者信息；节点有没有可能进入或者找到方法去找到控制端

#### 4.1.2 域名（不可能查得到的）：

域名的提供商-》有没有可能拿到信息

#### 4.1.3 攻击者的技术手段：

可以基本判断攻击者的技术水平和知识储备

#### 4.1.4 攻击时间（很多都是脚本自动跑）：

判断攻击者的常见时间

以上就是能够通过技术手段收集到的内容，接下来我们就需要使用非技术手段了。

### 4.2 非技术手段

#### 4.2.1 攻击者可能感兴趣的信息进行诱导

比如存放一些网站地址或者ip信息或者密码信息，但是这些信息都是指向蜜罐的

#### 4.2.2 根据自身业务内容逻辑存放攻击者感兴趣的东西

比如带宏的excel文档名字叫《公司财务规划总结》等

比如带恶意dll的oa客户端名字叫《XX公司内部通达OA系统安装包》等

#### 4.2.3 放一些可能会泄露在公开网络上的有趣的东西然后反向搜索信息最开始的发布点

比如在公司网络中的蜜罐里放上：“我是韩毅，红队没吃饭么”，然后反向搜索网上哪里是：“就tm你叫韩毅啊”的信息出处。
"""