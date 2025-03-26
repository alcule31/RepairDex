# RepairDex
android1代壳，二代函数抽取壳
无法dump下 insns时，更换脱壳时机，后续有需求更新此脚本
本脚本用来脱1代壳，二代函数抽取壳。此脚本目前二代脱壳点，在loadclassmemebrs脱壳时机较晚，
后续可以hook ExecuteSwitchCmplcpp来针对执行前加载codeitem的函数抽取壳。目前函数耦合度较高，
后续会将各模块单独分离，以适应不同情况。
