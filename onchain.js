var signTypeSetting=false;
function advancedSetup() {
	signTypeSetting = true;
	document.getElementById("multipleSignStyle").className = "signStyle floatLeft cur";
	document.getElementById("sigleSignStyle").style.display = "";
	document.getElementById("advancedSetupBlock").style.display = "none";
	document.getElementById("signSubmitStyle").className = "submitBody_backup";
}
function changeSignNameStyle(type) {
	if(!signTypeSetting){
		return;
	}
	if(type == 2){
		document.getElementById("multipleSignStyle").className = "signStyle floatLeft cur";
		document.getElementById("sigleSignStyle").className = "signStyle singleSign floatRight";
	}else if(type == 1){
		document.getElementById("multipleSignStyle").className = "signStyle floatLeft";
		document.getElementById("sigleSignStyle").className = "signStyle singleSign floatRight cur";
	}
	
}

var userSalt = null;
function getUserSalt(){
	if(!userSalt){
		console.log("ajax to get userSalt!")
		$.ajax({
			"url" : "/onchain/vault/getOnchainUserSalt.do", 
			"async" : false,
			"dataType" : "text",
			"success" : function(data){
				if(data == -1){
					alert("获取加盐密码失败！");
					userSalt = false;
				} else {
					userSalt = data;
				}
			}
		})
	} else {
		console.log("userSalt has existed !")
	}
	if(!userSalt){
		throw "获取加盐密码失败！";
	}
	return userSalt;
}


function encryptPassword(password) {
	var salt = getUserSalt();
	 password = Utils.AesEncrypt(password, salt);
	 var arrayByte = Utils.stringToBytes(password.toString());
	 var result = mnemonic.encode(arrayByte);
	 return result;
}

function decryptPassword(backupWorks) {
	var salt = getUserSalt();
	var bytes = mnemonic.decode(backupWorks);
	var encrytedString = Utils.bytesToString(bytes);
	var password = Utils.AesDecrypt(encrytedString, salt);
	return password.toString(Bitcoin.CryptoJS.enc.Utf8);
}

//上一步
function lastStep(stepNum, curNum) {
	$('#stepDiv_' + stepNum).hide();
	$('#stepDiv_' + (stepNum - 1)).show();
	
	if(curNum != undefined) {
		$('#cur_' + curNum).removeClass();
		$('#cur_' + (curNum - 1)).addClass('cur');
	}
	
}
//下一步
function nextStep(stepNum, curNum) {
	$('#stepDiv_' + stepNum).hide();
	$('#stepDiv_' + (stepNum + 1)).show();
	
	if(curNum != undefined) {
		$('#cur_' + curNum).removeClass();
		$('#cur_' + (curNum + 1)).addClass('cur');
	}
}

function selectTypeLastStep(){
	if(isVaultExist){
		$('#stepDiv_5').show();
		$('#stepDiv_3').hide();
		$('#cur_2').removeClass();
		$('#cur_1').addClass('cur');
	} else {
		lastStep(3, 2);
	}
}

function getVaultType(){
	if ($('#multipleSignStyle').hasClass('cur')) {
		return 2;
	}
	
	if($('#sigleSignStyle').hasClass('cur')) {
		return 1;
	}
}

function validateVaultName(nameId, tipsId) {
	var vaultName = $.trim($('#' + nameId).val());
	//校验保险柜名称  不多于20个字符  且不重复
	if (vaultName == ""){
		$('#' + tipsId).text(languageJson['valutnameisnull']);
		return false;
	} else if(vaultName.length > 20) {
		$('#' + tipsId).text(languageJson['vaultnaetoolong']);
		return false;
	}
	
	//正则判断是否含有特殊字符
	var regexp = new RegExp("^[a-zA-Z0-9\u4e00-\u9fa5]+$");
	if(vaultName.match(regexp)){
		
	} else {
		$('#' + tipsId).text("保险柜名称不能包含特殊字符！");
		return;
	}
	
	$('#' + tipsId).text("");
	var existed = true;
	$.ajax({
			 'url' : '/onchain/vault/guranteeAlias.do',
			 "type" : "post",
			 'data' : {'alias' : vaultName}, 
			 'async' : false,
			 "contentType": "application/x-www-form-urlencoded; charset=UTF-8",
			 'success' : function(data){
					if(data > 0) {
						$('#' + tipsId).text('此保险柜名称已存在！');
					} else {
						existed = false;
					}
				}
	});
	
	return !existed;
}

function createVault() {
	var vaultName = $.trim($('#vaultName').val());
	var legal = validateVaultName("vaultName", "safeNameErrorTips");
	
	if(!legal){
		return;
	}

	try{
		var ecKey = Bitcoin.ECKey.makeRandom();
	} catch(e){
		okcoinAlert(languageJson["ie11notsupport"]);
		throw e;
	}

	var password = '';
	if(isVaultExist) {
		password = $('#existedPassword').val();
	} else {
		password = $('#password').val();
	}
	
	var userSalt = getUserSalt();
	password += userSalt;
	password = Bitcoin.CryptoJS.MD5(password).toString();
	
	//加密后的私钥，若包含"/"等特殊字符，将被转码
	var encrytedPrivateKey = Utils.AesEncrypt(ecKey.toWIF(), password).toString();
	encrytedPrivateKey = encodeURIComponent(encrytedPrivateKey);
	var publicKey = ecKey.pub.toHex();
	var safeCabinetType = getVaultType();
	var multiSignMax = 1;
	var multiSignMin = 1;
	if(safeCabinetType == 2){
		 multiSignMax = 2;
		 multiSignMin = 2;
	}
	
	$.post('/onchain/vault/createVault.do',
			{
				'alias' : vaultName,
				'multiSignMax' : multiSignMax,
				'multiSignMin' : multiSignMin,
				'privateKey' : encrytedPrivateKey,
				'publicKey' : publicKey,
				'default' : !isVaultExist
			},
			function(data){
				data = JSON.parse(data)
				data = data.resultCode;
				if ( data >= 0) {
					if(isVaultExist){
						window.location.href = "/onchain/vault/showVaults.do"
					} else {
						window.location.href = "/onchain/index.do"
					}
				} else {
					$('#safeNameErrorTips').text('保险柜创建失败！');
				}
			}
	);
	
}

function validatePassword(inputId, tipsId, checkOldpw){
	var pwd = $.trim($('#' + inputId).val());
	var desc="";
	
	if (pwd == "") {
		desc = languageJson["coinOkRegPasswordNullError"];
	} else if (pwd.length < 6 || pwd.length > 30) {
		desc = languageJson["coinOkRegPasswordLengthError"];
	} else if (!/[a-zA-Z]/.test(pwd) || !/[0-9]/.test(pwd) || !/[^0-9a-zA-Z]/.test(pwd)) {
		desc = languageJson["coinOkRegPasswordRequiredError"]; // 密码至少应包含一个数字、字母和特殊字符
	} 
	
	if(desc != ""){
		if(checkOldpw && pwd != ""){
			desc = languageJson["onchainpwderror"];
		}
		$('#' + tipsId).text(desc).show();
		return false;
	} else {
		$('#' + tipsId).text("").hide();
		return true;
	}
	
}

function validateRePwd(tipsId) {
	var pwd =  $.trim($('#password').val());
	var rePwd = $.trim($('#repassword').val());
	var desc='';
	
	if(rePwd == ""){
		desc =  languageJson["coinOkRegRePasswordNullError"];
	} else if(pwd != rePwd){
		desc =  languageJson["coinOkRegRePasswordEqualsError"];
	}
	
	if(desc != ""){
		$("#" + tipsId).show();
		$('#safePasswordErrorTips').text(desc);
		$('#repassword').removeClass('success');
		return false;
	} else {
		$('#safePasswordErrorTips').text("");
		$('#repassword').addClass('success');
		return true;
	}
	
	
}

var UserDataCache = {};
//验证保险柜密码
function isPasswordCorrect(inputId, tipsId, vaultId, multiSign) {
	var correct = false;
	var password = $('#' + inputId).val();

	if(vaultId  == undefined){
		vaultId = 0;
	} else if(multiSign > 1) {
		var okPubKey = vaultId + "okPubKey";
	}
	
	//使用数据缓存，就不需要每次检查保险柜密码都发一次请求
	var result = [];
	if(UserDataCache[vaultId] == undefined || (okPubKey != undefined && UserDataCache[okPubKey] == undefined)) {
		var json = {};
		json["vaultId"] = vaultId;
		
		if(multiSign != undefined){
			json["multiSign"] = multiSign
		} else {
			json["multiSign"] = 1;
		}
		
		$.ajax({
			'url' : '/onchain/vault/getPrivatePasswordEN.do', 
			'async' : false,
			'data' : json,
			'success' : 	function(data){
										result = JSON.parse(data);
										UserDataCache[vaultId] = result["privateKey_en"];
								}
		});
	}
	
	var userSalt = getUserSalt();
	password += userSalt;
	password = Bitcoin.CryptoJS.MD5(password).toString();
	
	var decrypt = Utils.AesDecrypt(UserDataCache[vaultId], password);
	var privateKey = "";
	try {
		privateKey = decrypt.toString(Bitcoin.CryptoJS.enc.Utf8);
	} catch(e) {
		
	}
		
	if(privateKey != "") {
		//如果解密成功，把密码（可能包含okcoin公钥）返回
		result["privateKey_en"] = privateKey;
		if(okPubKey != undefined) {
			if(result["redeemscript"] != undefined){
				UserDataCache[okPubKey] = result["redeemscript"];
			} else {
				result["redeemscript"] = UserDataCache[okPubKey];
			}
		}
		return result;
	} else {
		$('#' + tipsId).text('保险柜密码错误，请重新输入！')
	}
	return correct;
}


function generateBackupWords(inputId, tipsId) {
	if(validatePassword(inputId, tipsId)) {
		//是否校验rePassword
		var passed = true;
		passed = validateRePwd(tipsId);
		
		if (passed) {
			//把保险柜密码加密，转换成英文单词串
			var pw = $('#' + inputId).val();
			var backupWords = encryptPassword(pw);
			if(!backupWords) {
				$('#' + tipsId).text("保险柜密码加密失败！");
				return;
			}
			$('#backupWords').text(backupWords);
			nextStep(1);
			$('#copyBackupWords').zclip({
				path: preUrl+ '/link/js/jquery/ZeroClipboard.swf',
				copy: $('#backupWords').text(),
		   });
		}
	}
}


function ckeckOriginalPassword(inputId, tipsId){
	if(validatePassword(inputId, tipsId, 'checkOldpw')) {
		//检测密码是否正确
		var passed = isPasswordCorrect(inputId, tipsId);
		if (passed) {
			nextStep(2, 1);
			$('#stepDiv_5').hide();
		} else {
			$("#" + tipsId).show();
		}
	}
}


function quickPayNextStep(){
	//检查币数
	if(!checkCoinAmount()){
		$("#orderAmount").focus();
		return;
	}
	
	var orderAmount = parseFloat($('#orderAmount').val());
	var $selectedVault = $('#selectVault').find("option:selected");
	var coinType = $("#orderAmountType").val();
	//检查手续费
	var minerFee = parseFloat($('#minerFee').val());
	if(isNaN(minerFee) || (coinType == 0 && minerFee < 0.0001) || (coinType == 1 && minerFee < 0.001)){
		okcoinAlert("请输入有效的手续费！");
		return;
	}
	var total = orderAmount + minerFee;
	//检查余额 
	var sourceAddr = $selectedVault.val();
	if(mode == "simpleMode") {
		if(coinType == 0){
			if(total > maxBtc){
				okcoinAlert("保险柜比特币余额不足！");
				return;
			}
		} else {
			if(total > maxLtc){
				okcoinAlert("保险柜莱特币余额不足！");
				return;
			}
		}
		$('#payFrom').hide();
		$('#changesTo').hide();
	} else {
		if(coinType == 0){
			var btc = parseFloat($selectedVault.attr("btcAmount"))
			if(total > btc){
				okcoinAlert("保险柜比特币余额不足！");
				return;
			}
		} else {
			var ltc = parseFloat($selectedVault.attr("LtcAmount"))
			if(total > ltc){
				okcoinAlert("保险柜莱特币余额不足！");
				return;
			}
		}
	    
		$('#sourceVault').text($selectedVault.text());
		$('#vaultOfChange').text($('#selectVaultOfChange').find("option:selected").text());
		
		$('#payFrom').show();
		$('#changesTo').show();
	}
	
	var typeStr = "";
	if(coinType == 0){
		typeStr = "BTC";
	} else {
		typeStr = "LTC";
	}
	
	if(targetAddressType == "wallet"){
		$('#targetAddressOfSpan').text($('#selectWallet').find("option:selected").text())
	} else if(targetAddressType == "address") {
		//校验输入的目的地址
		var targetAddr = $.trim($('#targetAddress').val());
		if(!Utils.isValidCoinAddress(targetAddr)){
			okcoinAlert("请输入有效的" + typeStr + "地址！");
			return;
		}
		
		if(sourceAddr == targetAddr){
			okcoinAlert("源保险柜地址和目的地址不能一样！");
			return;
		}

		$('#targetAddressOfSpan').text(targetAddr);
	}
	
	$('#quickpay').hide();
	$('#confirmDiv').show();
	$('#title').text('确认付款');
	$('#advancedLink').hide();

	$('#totalCoin').text(orderAmount + typeStr + " + " + minerFee + typeStr +"网络手续费")
}


function checkPasswordFormat(inputId, tipsId){
	if(!validatePassword(inputId, tipsId)){
		var tips = "";
		if($.trim($('#' + inputId).val()) == ""){
			tips = "请输入保险柜密码！"
		} else {
			tips = "保险柜密码错误，请重新输入！";
		}
		$('#' + tipsId).text(tips).show();
		return false;
	} else {
		$('#' + tipsId).hide();
		return true;
	}
}

function clickToPay(){
	var inputId = "vaultPassword";
	var tipsId = "passwordErrorTips";
	
	if(!checkPasswordFormat(inputId, tipsId)){
		return;
	}
	
	//校验保险柜密码
	var selectedVault = $("#selectVault").find("option:selected");
	var vaultId = 0;
	if(mode == "advanceMode"){
		vaultId = selectedVault.attr("vaultId");
	}
	
	var multiSignMax = parseInt(selectedVault.attr("multiSignMax"));
	var $selectVaultOfChange = $('#selectVaultOfChange');
	var changesAddr = "";
	var changesVaultId = 0;
	var coinType = parseInt($("#orderAmountType").val()) + 1;
	var coinAmount = 0;
	var orderAmount = Math.round(parseFloat($('#orderAmount').val()) * 100000000);
	if( isNaN(orderAmount) ){
		orderAmount = 0;
	}
	var minerFee =Math.round(parseFloat($('#minerFee').val()) * 100000000);
	coinAmount = orderAmount + minerFee;
	
	var checkSmsCode = $("#smsCodeCheck").is(":visible");
	var smsCode = $.trim($("#smsCode").val());
	if(checkSmsCode && smsCode == ""){
		$("#smsCode").focus();
		$("#smsCodeTip").text("请输入短信验证码").addClass("errorCueContent")
		return;
	}
	
	var checkGoogleCode = $("#googleCodeCheck").is(":visible");
	var googleCode = $.trim($("#googleCode").val());
	if(checkGoogleCode && googleCode == ""){
		$("#googleCodeTip").focus();
		$("#googleCodeTip").text("请输入谷歌验证码").addClass("errorCueContent")
		return;
	}
	
	if(!checkSmsCode && !checkGoogleCode){
		okcoinAlert("未开启二次验证！")
		return;
	}
	
	setButtonInProcess('submitBtn');
	
	$.ajax({
		"url" : "/onchain/pay/chooseBitcoinInputs.do",
		"data" : {
			"money" : Math.round(coinAmount),
			"vault_id" : vaultId,
			"coin_type" : coinType
		},
		success : function(inputsString){
			var inputs = null;
			if(inputsString != null && inputsString != "null"){
				inputs = eval("(" + inputsString + ")");
			}
			if(inputs != null){
				 if(inputs instanceof Array) {
					 if(inputs.length > 0){
						 if(mode == "simpleMode"){
							 vaultId = inputs[0].vaultid;
							 changesAddr = inputs[0].addressTo;
							 changesVaultId = vaultId;
						 } else {
							 changesAddr = $selectVaultOfChange.val();
							 changesVaultId = $selectVaultOfChange.find("option:selected").attr("vaultId");
						 }
					 }
				 } else {
					 okcoinAlert("获取input交易失败，用户未登录。 返回信息： " + inputs);
					 setButtonFinish('submitBtn', languageJson['confirm']);
					 return ;
				 }
			 } else {
				 okcoinAlert('保险柜余额不足！');
				 setButtonFinish('submitBtn', languageJson['confirm']);
				 return;
			 }
			
			try{
				  //取userSalt可能会抛异常
				  var result = isPasswordCorrect(inputId, tipsId, vaultId, multiSignMax);
				  if(!result) {
					$('#' + tipsId).text('保险柜密码错误，请重新输入！').show();
					throw "Password is invalid";
				  } else {
					$('#' + tipsId).hide();
				  }
			  } catch(e){
				  	$('#' + tipsId).text('密码校验失败，请重试！').show();
				  	setButtonFinish('submitBtn', languageJson['confirm']);
			    	return;
			  }finally{
				  
			  }
			
			//构建交易单，签名
			var txBuilder = new Bitcoin.TransactionBuilder();
			var totalInput = 0;
			for(var i in inputs){
				 	txBuilder.addInput(inputs[i].txid, inputs[i].index);
					totalInput += parseInt(inputs[i].amount);
			}
			 
			 var targetAddress = "";
			 if(targetAddressType == "wallet"){
				targetAddress = $('#selectWallet').val();
			  } else if(targetAddressType == "address") {
				targetAddress = $.trim($('#targetAddress').val());
			 }
			 
			 txBuilder.addOutput(targetAddress, orderAmount);
			 //找零
			 var changes = totalInput - coinAmount;
			 if(changes > 0){
				 txBuilder.addOutput(changesAddr, changes);
			}

			 var signatures = {};
			 //sign
			 var privateKey = result["privateKey_en"];
			 privateKey = Bitcoin.ECKey.fromWIF(privateKey);

			 var redeemScript = result["redeemscript"];
			 if(redeemScript != undefined){
				 if(redeemScript != ""){
					 redeemScript = Bitcoin.Script.fromHex(redeemScript);
				 } else {
					 redeemScript = undefined;
				 }
			 }
			 for(var i = 0; i < txBuilder.tx.ins.length ; i++){
				 txBuilder.sign(i, privateKey, redeemScript);
				 signatures[i] = txBuilder.signatures[i].signatures[0].toDER().toString("hex");
			 }
			 
			 var tx = null;
			 if(multiSignMax == 1){
				 tx = txBuilder.build();
			 } else if(multiSignMax >1 ) {
				 tx = txBuilder.buildIncomplete();
			 }
			 
			 var txHex = tx.toHex();
			 var txid = tx.getId();
			  $.post(
				   "/onchain/pay/handlePayOrder.do",
				   {
					  "inputTrans" :  encodeURIComponent(inputsString),
					  "tran" :  encodeURIComponent(JSON.stringify({
						  "txid" : txid,
						  "coinType" : coinType,
						  "vaultid" : vaultId,
						  "addressTo" : targetAddress,
						  "fee" : minerFee,
						  "amount" : orderAmount,
						  "comments" : $("#remark").val(),
						  "changeMoney" : changes,
						  "changeVaultId" : changesVaultId
					  })),
					  "preTransaction" : txHex,
					  "partSignatures" : encodeURIComponent(JSON.stringify(signatures)),
					  "googleCode" : googleCode,
					  "phoneCode" : smsCode
				  },
				  function(data){
					  var result = JSON.parse(data);
					  if(result.resultCode == 0){
						  var paramsJson = {};
						  paramsJson.txid = txid;
						  paramsJson.targetAddr = targetAddress;
						  paramsJson.coin = orderAmount/100000000;
						  paramsJson.coinType = coinType;
						  paramsJson.id = result.objectId;
						  
						  window.location.href="/onchain/pay/paySuccess.do?" + $.param(paramsJson);
					  } else {
						  var smsInputId = "smsCode";
						  var smsTip = "smsCodeTip";
						  var googleInpuId = "googleCode";
						  var googleTip = "googleCodeTip";
						  if(result.resultCode == -17||result.resultCode == -18||result.resultCode == -19){
								okcoinTipAlert(smsInputId, smsTip, result);
						  }else if(result.resultCode == -20||result.resultCode == -21||result.resultCode == -22||result.resultCode == -23){
								okcoinTipAlert(googleInpuId, googleTip, result);
						  }else{
								okcoinTipAlert(smsInputId, smsTip, result);
								$("#" + smsTip).text("付款操作失败，请重试！")
						  }
						  setButtonFinish('submitBtn', languageJson['confirm']);
					  }
					  console.log("点击确认后， 返回的信息： " + data);
				  }
			  );

		},
		"error" : function(data){
			okcoinAlert("付款失败，请重试！");
			setButtonFinish('submitBtn', languageJson['confirm']);
		}
	});

}


