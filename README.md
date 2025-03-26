# RepairDex
android1代壳，二代函数抽取壳
无法dump下 insns时，更换脱壳时机，后续有需求更新此脚本
        本脚本用来脱1代壳，二代函数抽取壳。此脚本目前二代脱壳点，在loadclassmemebrs脱壳时机较晚，
    后续可以hook ExecuteSwitchCmplcpp来针对执行前加载codeitem的函数抽取壳。目前函数耦合度较高，
    后续会将各模块单独分离，以适应不同情况。
关键类：
                DexFile： 用来解析Dex文件获取关键字段地址。

                    filed：
                        DexHeader：dex文件头。
                        methodIdsOff:  基址，索引地址为基址+（偏移-1）x8
                        stringIdsOff:  基址，基址，索引地址为基址+（偏移-1）x4 
                        typesIdasOff: 用来获取类名。值为stringids中的索引

                ArtMethod： 用来解析artmethod对象，获取关键字段地址。
                    filed：
                        artMethodPtr;
                        method_idx : 获取当前method 的索引值。
                        dex_code_item_offest： 获取当前method_code的偏移。
                        
                Handle_class: 用来解析模板类中属性为class 的参数，获取其中的methods_.
                    filed:
                        mirror_class
                        methods_ : 本类所有的artmethod数组。对象内存中前8位是元素个数，后续为artmethod，每个artmethod占40字节
                        dexcache    ： 用来获取当前类的dexcache。目前没用后续有需要添加相关逻辑
                        location_str： 用来获取dex文件的本地地址。
                        dex_class_def_idx ： 用来获取当前类的索引值。
                  
                CodeItem ： 用来解析获取的codeitem，
                    filed:
                        insns：当前函数的字节码，2字节为单位
                        insns_size： 当前函数字节码长度，内存长度为：insns*2
                
                MemoryTools ：用来dump内存数据。
                    function:
                        dumpDexFile：
                            根据构造函数传进参数来判断，如果是DexFile类型调用该函数，在函数开头进行判断，是否在dumpList里，如果不在进行dump
                        防止重复dump。
                NativeTool ：用来进行批量主动调用，在静态函数中，进行dlopen和dlsym符号的获取。getFucArry（）为主函数，进行批量调用，
                        函数参数为1.sopath 2.二维数组， 内部数组为1.函数名，2.返回值类型3.参数数组[]
                
                InitNativeEnv : 用来进行art中关键函数的地址获取。在脚本运行之初与NativeTool进行初始化
                
               Notice! 
                     hook loadMethod是用来获取artMethod
                     hook allocDexCache 是来获取DexCache，用来与artmethod中的class属性来
                     对应验证，获取，dexcache偏移与loacation偏移。

                  1. getDlopen() 用来获取dlopen和dlsym符号，主动调用。
                  
                  2. activeCall（） 用来批量主动调用so文件中的函数。
                        soPath:所调用so库名;
                        args[[]]:二维数组,批量获取
                        args[0]['函数符号名','返回值：int',参数数组['int','pointer']] 
                  
                  5. artMethod对象中的属性偏移：
                            1.偏移0 为mirror::class 对象。
                            2.偏移4 为access_flag
                            3.偏移8 为dex_code_item_offest
                            4.偏移12 为 dex_method_idx 

                  6. mirror::class对象中的属性偏移：
                            1.偏移16 为 dexcache对象。
                            2.偏移48 为 methods_对象。为LengthPrefixedArray对象，其内存布局：
                                                                            [| 元素个数：8字节 | artmethod1| artmethod2 |]
                  7. dexCache对象中的属性偏移：
                            1.偏移8 为  HeapReference<String> location          
                            2.偏移16 为 DexFile
                            3.偏移48 为 resolved_methods_ 也就是该dex文件中的所有artmethod
