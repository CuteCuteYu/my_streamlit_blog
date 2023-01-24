import streamlit as st

"""
# 代码审计简单的小提示

------

## 1.代码审计需要的东西

### 1.1 软件：

1.1.1 文本编辑器：

notepad++、sublime、PHP storm

1.1.2 代码运行环境：

phpstudy

1.1.3 辅助审计工具：

kunlunM，seay

### 1.2 知识：

1.2.1 前端语言知识：

html、css、js

1.2.2 脚本语言知识：

php、asp、jsp

1.2.3 后端语言知识：

python->django、flask

java->vue、spring

1.2.4 数据库知识：

数据库语句、数据库结构、数据库使用

1.2.5 网站结构知识：

mvc等（如cms的基本结构）

## 2.代码审计的基本流程

2.1 了解目标的基本组织结构，也就是通读文件夹，知道哪些文件夹里面大概是哪些内容并且具体负责什么功能

2.2 寻找主要的入口页面（如index、admin等）找到前端页面逻辑触发的入口

2.3 遍历所有的功能函数并且了解基本的传参过程和内部处理逻辑

2.4 搭建运行环境并且收集所有用户可以控制的变量和参数

2.5 将收集到的变量和参数对照源代码带入并检查过滤机制

## 3.常见的漏洞点和源代码的关系

### 3.1 寻找技巧：

搜索引擎 “脚本语言+危险函数“

### 3.2 基本的漏洞机制：

注入->用户输入不受控制并且能拼接上开发者原本代码

文件上传等->黑白名单不完善或者缺失

反序列化->类的关联和敏感函数

逻辑漏洞等->参数类型没有问题但是影响业务风险

## 4.总结

耐心、细心
"""