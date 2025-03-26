/*
README: 无法dump下 insns时，更换脱壳时机，后续有需求更新此脚本
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
             
                            
                     _oo0oo_
                    o8888888o
                    88" . "88
                    (| -_- |)
                    0\  =  /0
                  ___/`---'\___
                .' \\|     |// '.
               / \\|||  :  |||// \
              / _||||| -:- |||||- \
             |   | \\\  -  /// |   |
             | \_|  ''\---/''  |_/ |
             \  .-\__  '-'  ___/-. /		   
           ___'. .'  /--.--\  `. .'___		   
        ."" '<  `.___\_<|>_/___.' >' "".	   
       | | :  `- \`.;`\ _ /`;.`/ - ` : | |	   
       \  \ `_.   \_ __\ /__ _/   .-` /  /	   
   =====`-.____`.___ \_____/___.-`___.-'=====  
                     `=---='				   
                                               
                                               
   ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ 
                                               
             佛祖保佑         永无BUG           

            

*/
let packageName = 'com.ninemax.ncsearchnew'
class ColorConsole {

    static reset = "\x1b[0m"
    static red = "\x1b[31m"
    static green = "\x1b[32m"
    static yellow = "\x1b[33m"
    static blue = "\x1b[34m"
    static magenta = "\x1b[35m"
    static cyan = "\x1b[36m"
    static white = "\x1b[37m"
    static gray = "\x1b[90m"
    static colorLog(message, color) {
        console.log(`${color || ColorConsole.reset}${message}${ColorConsole.reset}`);
    }
}
class NativeTool {
    static dlopen;
    static dlsym;
    static mmap
    static mmap_addr;
    /*此函数是用来获取dlopen和dlsym。*/

    static getLibcFuc() {
        try {
            NativeTool.dlopen = new NativeFunction(Module.findExportByName('libdl.so', 'dlopen'), 'pointer', ['pointer', 'int']);
            NativeTool.dlsym = new NativeFunction(Module.findExportByName('libdl.so', 'dlsym'), 'pointer', ['pointer', 'pointer'])
            NativeTool.mmap_addr = Module.findExportByName("libc.so", 'mmap');
            NativeTool.mmap = new NativeFunction(NativeTool.mmap_addr, 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'int'])
            ColorConsole.colorLog("dlopen,dlsym init success!!", ColorConsole.green)

        } catch (error) {
            ColorConsole.colorLog("dlopen,dlsym init error!!", ColorConsole.red)
        }
    }
    /* 此函数是主动调用so层函数,
    soPath:所调用so库名;
    args[[]]:二维数组,批量获取
    args[0]['函数符号名','返回值：int',参数数组['int','pointer']]
    返回值为所求主动调用函数的地址数组 */
    static getFucArry(soPath, args) {
        let fucArr = []
        let pathStr = Memory.allocUtf8String(soPath)
        let handle = NativeTool.dlopen(pathStr, 1)
        for (let i = 0; i < args.length; i++) {
            let fucFiled = []
            let fucName = Memory.allocUtf8String(args[i][0])
            let fuc = NativeTool.dlsym(handle, fucName)
            if (fuc.isNull()) {
                console.log("dont find fuc in your so file!!!!")
            } else {
                let fucAddr = new NativeFunction(fuc, args[i][1], args[i][2])
                fucFiled.push(args[i][0])
                fucFiled.push(fucAddr)
                fucArr.push(fucFiled)
            }
        }
        return fucArr
    }
    static getCmd(cmd_str) {
        let systems = NativeTool.getFucArry('system/lib64/libc.so', [['popen', 'pointer', ['pointer', 'pointer']], ['fgets', 'pointer', ["pointer", "int", "pointer"]], ['fclose', "int", ['pointer']]])
        if (systems == undefined) {
            ColorConsole.colorLog("get systemCmd is error !!", ColorConsole.red)
        } else {
            let output = ''
            let myPopen = systems[0][1];
            let myFgets = systems[1][1];
            let myFclose = systems[2][1];
            let cmdStr = Memory.allocUtf8String(cmd_str)
            let mode = Memory.allocUtf8String('r')
            let buffer = Memory.alloc(1024);
            let pipe = myPopen(cmdStr, mode)
            while (!myFgets(buffer, 1024, pipe).isNull()) {
                output += Memory.readUtf8String(buffer)
            }
            return output
        }
    }
    //无效
    static setMemoryProtect() {
        Interceptor.replace(NativeTool.mmap_addr, new NativeCallback(function (arg1, arg2, arg3, arg4, arg5, arg6) {
            let result

            if (arg3 == 0x1 && arg1 != 0x0) {
                console.log(arg1)
                result = NativeTool.mmap(arg1, arg2, 0x0, arg4, arg5, arg6)
            } else {
                result = NativeTool.mmap(arg1, arg2, arg3, arg4, arg5, arg6)
            }
            return result
        }, 'pointer', ['pointer', 'size_t', 'int', 'int', 'int', 'int']))
    }
}
NativeTool.getLibcFuc()
//NativeTool.setMemoryProtect()
class InitNativeEnv {
    static moudleAddr = Process.findModuleByName('libart.so')
    static fuc_loadMethod = null;
    static fuc_allocDexcache = null;
    static fuc_switch = null;
    static fuc_init = null
    static fuc_alloca_artmethod_array = null;
    static fuc_MapFileAtAddress = null;
    static init() {
        let symbles = InitNativeEnv.moudleAddr.enumerateSymbols()

        for (let symble of symbles) {
            if (symble.name.indexOf('_ZN3art11ClassLinker10LoadMethodERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE') != -1) {// hook loadmethod
                InitNativeEnv.fuc_loadMethod = symble.address
            } else if (symble.name.indexOf('_ZN3art11ClassLinker13AllocDexCacheEPNS_6ObjPtrINS_6mirror6StringEEEPNS_6ThreadERKNS_7DexFileE') != -1) {
                InitNativeEnv.fuc_allocDexcache = symble.address
            } else if (symble.name.indexOf('_ZN3art11ClassLinker16LoadClassMembersEPNS_6ThreadERKNS_7DexFileEPKhNS_6HandleINS_6mirror5ClassEEE') != -1) {
                InitNativeEnv.fuc_switch = symble.address
            } else if (symble.name.indexOf('_ZN3art6mirror8DexCache4InitEPKNS_7DexFileENS_6ObjPtrINS0_6StringEEEPNSt3__16atomicINS0_12DexCachePairIS6_EEEEjPNS9_INSA_INS0_5ClassEEEEEjPNS9_INS0_18NativeDexCachePairINS_9ArtMethodEEEEEjPNS9_INSI_INS_8ArtFieldEEEEEjPNS9_INSA_INS0_10MethodTypeEEEEEjPNS_6GcRootINS0_8CallSiteEEEj') != -1) {
                InitNativeEnv.fuc_init = symble.address
            } else if (symble.name.indexOf('_ZN3art11ClassLinker19AllocArtMethodArrayEPNS_6ThreadEPNS_11LinearAllocEm') != -1) {
                InitNativeEnv.fuc_alloca_artmethod_array = symble.address
            } else if (symble.name.indexOf('_ZN3art6MemMap16MapFileAtAddressEPhmiiilbbPKcPNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEE') != -1) {
                InitNativeEnv.fuc_MapFileAtAddress = symble.address
            }
        }
    }
}
InitNativeEnv.init()
class DexFile {
    static dexfileData = {};
    dexfilePtr;   //当前 dexFile 的指针
    dexFileHeader;
    dexFileSize;
    dexFileMagic;
    dexFileCheckSum;
    methodIdsOff;  //基址，索引地址为基址+（偏移-1）x8
    stringIdsOff; // 基址，基址，索引地址为基址+（偏移-1）x4
    typesIdasOff;
    codeItem;
    //dumpSwitch添加是否dump的开关，防止出现每个dexfile只加载一次，从而dexfile初始化不成功。
    //不需要dump时，dumpSwitch设置为false    
    constructor(dexfile) {
        this.dexfilePtr = ptr(dexfile)
        this.dexFileHeader = this.dexfilePtr.add(8).readPointer()
        this.dexFileMagic = this.dexFileHeader.readU16()
        if (this.dexFileMagic != 25956) {
            throw new Error("this dexFile dont legal!")
        }
        this.dexFileCheckSum = this.dexFileHeader.add(8).readU32()
        this.methodIdsOff = this.dexFileHeader.add(this.dexFileHeader.add(92).readU32());//得到内存中method_ids_off的偏移
        this.stringIdsOff = this.dexFileHeader.add(this.dexFileHeader.add(60).readU32())//得到内存中string_ids_off的偏移
        this.typesIdasOff = this.dexFileHeader.add(this.dexFileHeader.add(68).readU32())//得到内存中types_ids_off的偏移
        this.dexFileSize = this.dexFileHeader.add(32).readU32()
        new MemoryTools(this)
    }
    getMethodName(method_idx) {
        let method_name_idx_off = this.methodIdsOff.add((method_idx - 1) * 8 + 4).readU32()//得到当前methodName在stringidx中的索引
        return this.readString(method_name_idx_off)
    }
    getClassName(method_idx) {
        let class_name_idx = this.methodIdsOff.add((method_idx - 1) * 8).readU16()
        let typ_idx_off = this.typesIdasOff.add(((class_name_idx - 1) * 4)).readU32()
        return this.readString(typ_idx_off)
    }
    readString(idx) {
        let idx2Off = (idx - 1) * 4
        let stringPtr = this.dexFileHeader.add(this.stringIdsOff.add(idx2Off).readU32())
        let string = stringPtr.add(1).readCString()
        return string
    }
    getMehodAllName(method_idx) {
        let class_name = this.getClassName(method_idx)
        let method_name = this.getMethodName(method_idx)
        return class_name + "-> " + method_name + '()'
    }

    getMethodCodeItem(code_off) {
        let code_off_ = this.dexFileHeader.add(code_off)
        this.codeItem = new CodeItem(code_off_)
        return this.codeItem
    }
    SaveDexCodeInsns() {
        let save = new SaveCode(this);
        save.write("" + this.codeItem.code_off_.sub(this.dexFileHeader).add(16) + ":" + new Uint8Array(this.codeItem.insns) + ';')
        save.flush()
    }
}
class SaveCode {
    static openFile = {}
    static checksum = []
    constructor(dexfile) {
        if (SaveCode.checksum.includes(dexfile.dexFileCheckSum)) {
            return SaveCode.openFile[dexfile.dexFileSize]
        } else {
            let file = new File("data/data/" + packageName + '/' + dexfile.dexFileSize + '.txt', 'w')
            SaveCode.openFile[dexfile.dexFileSize] = file
            SaveCode.checksum.push(dexfile.dexFileCheckSum)
            return file
        }
    }


}
class CodeItem {
    static insns_size
    insns
    code_off_
    constructor(code_off) {
        this.code_off_ = code_off
        this.insns_size = code_off.add(12).readU32()
        if (this.insns_size > 200) {
            this.insns = null
        } else {
            try {
                this.insns = code_off.add(16).readByteArray(this.insns_size * 2)
            } catch (error) {

            }
        }
    }
}
//解析artMethod中主要属性的偏移。并且获取当前apk包名。
class ArtMethod {
    artMethodPtr;
    method_idx;
    dex_code_item_offest;
    constructor(artMethod_data) {
        this.artMethodPtr = ptr(artMethod_data)
        this.method_idx = this.artMethodPtr.add(12).readU16()
        this.dex_code_item_offest = this.artMethodPtr.add(8).readU32()
    }
}
// 后续添加dump 内存中so文件具体代码，目前占位
class So_elf {
}
// 用来dump内存中的dex和elf文件，后续添加其他相关内存操作。
class MemoryTools {
    static file_path;
    static dexFileList = [];
    dexfile_parse;
    so_elf;
    dumpMemory(baseAddr, fileSize, filepath) {
        try {
            let file = new File(filepath + '.dex', 'wb')
            file.write(baseAddr.readByteArray(fileSize))
            file.flush()
            file.close()
            let file_2 = new File(filepath + '.txt', 'wb')
            file_2.close()
            return true
        } catch (error) {
            return false
        }
    }

    dumpDexFile() {
        /*         let cmd_str = 'su&&ls data/data/' + packageName + '/'
                console.log(NativeTool.getCmd(cmd_str)) */
        if (MemoryTools.dexFileList.includes(this.dexfile_parse.dexFileCheckSum)) {
            return;
        } else {
            DexFile.dexfileData[this.dexfile_parse.dexFileSize] = []
            let flag = this.dumpMemory(this.dexfile_parse.dexFileHeader, this.dexfile_parse.dexFileSize, MemoryTools.file_path)
            if (flag) {
                MemoryTools.dexFileList.push(this.dexfile_parse.dexFileCheckSum)
                console.log("dump dex success! filePath: " + MemoryTools.file_path + " fileName: " + this.dexfile_parse.dexFileSize + ".dex")
            }
        }
    }
    constructor(memory) {
        if (memory instanceof DexFile) {
            this.dexfile_parse = memory
            MemoryTools.file_path = 'data/data/' + packageName + '/' + this.dexfile_parse.dexFileSize
            this.dumpDexFile()
        } else if (memory instanceof So_elf) {
            this.so_elf = new So_elf(memory)
        }
    }
}
//该类用来解析mirror::class用来获取类中所有的Artethod
class Handle_class {
    mirror_class
    methods_
    dexcache
    location_str
    dex_class_def_idx
    static instanceCount = 0
    constructor(handle_kclass) {
        this.mirror_class = handle_kclass.readPointer()
        this.methods_ = this.mirror_class.add(48).readPointer()
        this.dexcache = this.mirror_class.add(16).readPointer()
        this.location_str = ptr(this.dexcache.add(8).readU32()).add(16).readCString()
        this.dex_class_def_idx = this.mirror_class.add(80).readU32()
        /*         if (Handle_class.instanceCount == 0) {
                    console.log(this.location_str)
                    let regex = '(com.*?)[/-]' //正达参数
                    let matches = this.location_str.match(regex)
                    Handle_class.packageName = matches[1]
                    Handle_class.instanceCount+=1
                } */
    }
    parseMethods_(dexfile) {
        let methodNum = this.methods_.readU32()
        let methodArrBaseAddr = this.methods_.add(8)
        for (let i = 0; i < methodNum; i++) {
            let art = new ArtMethod(methodArrBaseAddr.add(40 * i))
            let art_method_idx = art.method_idx
            let methodName = dexfile.getMehodAllName(art_method_idx)
            let methodCodeInsns = dexfile.getMethodCodeItem(art.dex_code_item_offest)
            dexfile.SaveDexCodeInsns()
            let uint8Array = new Uint8Array(methodCodeInsns.insns)
            // console.log(uint8Array + " method_idx: "+art.method_idx +" class_dex_idx: "+ this.dex_class_def_idx+" insns_size: "+CodeItem.insns_size)
        }
    }
}
function repairDexFile_ins() {
    Java.perform(function () {
        let dexFileList = []
        var RandomAccessFile = Java.use('java.io.RandomAccessFile');
        var FileReader = Java.use('java.io.FileReader');
        var BufferedReader = Java.use('java.io.BufferedReader');
        var File = Java.use('java.io.File');
        // 设置你要列出文件的目录路径
        var dirPath = '/data/data/' + packageName;  // 请根据目标应用的实际路径调整
        // 创建一个 File 对象
        var dir = File.$new(dirPath);
        // 获取目录下的所有文件和子目录
        var files = dir.listFiles();
        // 打印文件列表
        if (files !== null) {
            for (var i = 0; i < files.length; i++) {
                if (files[i].getName().toString().indexOf('.dex') != -1) {
                    dexFileList.push(files[i].getName().toString())
                }
            }
        } else {
            console.log("目录为空或无法访问");
        }
        for (let i = 0; i < dexFileList.length; i++) {
            let fileSize = parseInt(dexFileList[i].split('.')[0])
            var file = RandomAccessFile.$new(dirPath + '/' + dexFileList[i], "rw");
            var fileReader = FileReader.$new(dirPath + '/' + dexFileList[i].split('.')[0] + '.txt');
            var bufferedReader = BufferedReader.$new(fileReader);

            // 读取文件内容
            var line;
            var fileContent = "";
            while ((line = bufferedReader.readLine()) !== null) {
                fileContent += line + "\n";
            }
            // 关闭文件
            bufferedReader.close();
            fileReader.close();
            let insnArray = fileContent.split(';')
            for (let i = 0; i < insnArray.length; i++) {
                let array = insnArray[i].split(':')
                let offset = parseInt(array[0])
                if (!isNaN(offset) && offset < fileSize) {
                    if (!array[1] == '') {
                        file.seek(offset)
                        if (offset > 10000000) {
                            console.log(offset)
                        }
                        let cc = array[1].split(',').map(function (num) {
                            return parseInt(num)
                        })
                        if (cc != "") {
                            let javaByteArray = Java.array('byte', cc);
                            file.write.overload('[B').call(file, javaByteArray)

                        } else {
                            console.log("error")
                        }
                    } else {

                    }
                }
            }
            console.log(dirPath + '/' + dexFileList[i] + '.dex  repair success!!!')
            file.close()

        }
    })


}
function hook() {
    let dexFile;
    let kclass;
    let dexFile_parse;
    //repairDexFile_ins()
    Interceptor.attach(InitNativeEnv.fuc_switch, {
        onEnter: function (args) {
            dexFile = args[2]
            kclass = args[4]
        }, onLeave: function () {
            let kclass_parse = new Handle_class(kclass)
            try {

                dexFile_parse = new DexFile(dexFile)
            } catch (error) {
                if (!error.meessage == "this dexFile dont legal!") {
                    console.log(error.message)
                }
            }
            if (dexFile_parse != undefined) {
                kclass_parse.parseMethods_(dexFile_parse)

            }
        }
    }

    )
    //修复Dex 先生成ins.txt 最后调用此函数修复dex
    // repairDexFile_ins()

}
setImmediate(hook)
