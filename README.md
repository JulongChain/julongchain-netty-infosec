# Forked Netty 

一个Fork的Netty版本，主要用于支持国密SSL


## How to build

编译方法和官方版本的方法是一样的

## What we changed

* 主要修改了handler模块，该模块负责网络通信
* 需要配合netty-tcnative模块，才可以使用国密SSL
* 不影响原来的SSL功能
* 将本项目编译出来的Jar和netty-tcnative编译出来的Jar放到要使用的项目中，替换原来对官方Netty的引用即可

更多修改内容请查看提交日志