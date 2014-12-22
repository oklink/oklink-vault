/**
 * Created by OK on 2014/9/18.
 */

//OKkey = "okcoinwallet"

//解决ie10以下的浏览器不支持Int32Array的问题
if(typeof(Int32Array) == "undefined")
{
    Int32Array = function(size)
    {
        if(size < 0 || Math.floor(size) != size) { throw "Invalid array length"; } 
        for(var index = 0; index < size; index++) { this[index] = 0; }
        this.length = size;
    };
    Int32Array.prototype = new Array();
}


Binary={
    stringToBytes:function(e){for(var t=[],n=0;n<e.length;n++)t.push(e.charCodeAt(n));return t},
    bytesToString:function(e){for(var t=[],n=0;n<e.length;n++)t.push(String.fromCharCode(e[n]));return t.join("")}
}


Utils = {
    stringToBytes:function(e){return Binary.stringToBytes(unescape(encodeURIComponent(e)))},
    bytesToString:function(e){return decodeURIComponent(escape(Binary.bytesToString(e)))},

    AesEncrypt : function (data, key){
        var encryptedData = Bitcoin.CryptoJS.AES.encrypt(data, key);
        return encryptedData;
    },

    AesDecrypt : function (encrytedData, key){
        var data = Bitcoin.CryptoJS.AES.decrypt(encrytedData, key);
        return data;
    },
    
    Litecoin : {
        magicPrefix: '\x19Litecoin Signed Message:\n',
        bip32: {
            public: 0x019da462,
            private: 0x019d9cfe
        },
        pubKeyHash: 0x30,
        scriptHash: 0x05,
        wif: 0xb0,
        dustThreshold: 0,
        dustSoftThreshold: 100000,
        feePerKb: 100000
    },
    
    testnet: {
        magicPrefix: '\x18Bitcoin Signed Message:\n',
        bip32: {
            public: 0x043587cf,
            private: 0x04358394
        },
        pubKeyHash: 0x6f,
        scriptHash: 0xc4,
        wif: 0xef,
        dustThreshold: 546,
        feePerKb: 10000
    },
    
    //格式化CST日期的字串
    formatCSTDate : function (strDate,format){
      return formatDate(new Date(strDate),format);
    },
     
    //格式化日期,
    formatDate : function (date,format){
      var paddNum = function(num){
        num += "";
        return num.replace(/^(\d)$/,"0$1");
      }
      //指定格式字符
      var cfg = {
         yyyy : date.getFullYear() //年 : 4位
        ,yy : date.getFullYear().toString().substring(2)//年 : 2位
        ,M  : date.getMonth() + 1  //月 : 如果1位的时候不补0
        ,MM : paddNum(date.getMonth() + 1) //月 : 如果1位的时候补0
        ,d  : date.getDate()   //日 : 如果1位的时候不补0
        ,dd : paddNum(date.getDate())//日 : 如果1位的时候补0
        ,hh : paddNum(date.getHours())  //时
        ,mm : paddNum(date.getMinutes()) //分
        ,ss : paddNum(date.getSeconds()) //秒
      }
      format || (format = "yyyy-MM-dd hh:mm:ss");
      return format.replace(/([a-z])(\1)*/ig,function(m){return cfg[m];});
    },
    
    isValidCoinAddress : function(addr){
    	try{
    		Bitcoin.Address.fromBase58Check(addr);
    		return true;
    	} catch(e){
    		return false;
    	}
    }

}
