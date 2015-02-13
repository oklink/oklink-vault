var signTypeSetting=false;
function advancedSetup() {
	signTypeSetting = true;
	document.getElementById("multipleSignStyle").className = "signStyle floatLeft cur";
	document.getElementById("sigleSignStyle").style.display = "";
	document.getElementById("advancedSetupBlock").style.display = "none";
	//document.getElementById("signSubmitStyle").className = "submitBody_backup";
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
					okcoinAlert(languageJson['languageJson']);
					userSalt = false;
				} else {
					userSalt = data;
				}
			}
		})
	}
	if(!userSalt){
		throw languageJson['languageJson'];
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
	//校验保险柜名称  不多于10个字符  且不重复
	if (vaultName == ""){
		$('#' + tipsId).text(languageJson['valutnameisnull']);
		return false;
	} else if(vaultName.length > 10) {
		$('#' + tipsId).text(languageJson['vaultnaetoolong']);
		return false;
	}
	
	//正则判断是否含有特殊字符
	var regexp = new RegExp("^[a-zA-Z0-9\u4e00-\u9fa5]+$");
	if(vaultName.match(regexp)){
		
	} else {
		$('#' + tipsId).text(languageJson['vaultIllegalCharater']);
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
						$('#' + tipsId).text(languageJson['vaultNameExist']);
					} else {
						existed = false;
					}
				}
	});
	
	return !existed;
}

function createVault() {
	try{
		setButtonInProcess('createBtn');
		var vaultName = $.trim($('#vaultName').val());
		var legal = validateVaultName("vaultName", "safeNameErrorTips");
		if(!legal){
			throw "okException: illegalVaultName";
		}
		
		try{
			var ecKey = Bitcoin.ECKey.makeRandom();
		} catch(e){
			okcoinAlert(languageJson['ie11notsupport']);
			throw "okException: ie11notsupport";
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
						$('#safeNameErrorTips').text(languageJson['vaultCreateFail']);
						setButtonFinish('createBtn', languageJson['finish']);
					}
				}
		);
	}catch(e){
		setButtonFinish('createBtn', languageJson['finish']);
		if(e.toString().indexOf("okException") == -1){
			okcoinAlert(languageJson['clickError']);
		}
		console.log(e.toString());
	}

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
		$('#' + tipsId).text(languageJson['onchainpwderror'])
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
				$('#' + tipsId).text(languageJson['vaultPWDCrptoFail']);
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
	
	//判断全局单位是否为mbtc,mltc
	var isMilliUnit = $('#isMilliUnit').val() == 1;
	
	//检查留言
	var remark = $.trim($("#remark").val());
	var remarkToBlock = $("#remarkToBlock").attr("checked");
	if(remarkToBlock){
		if(remark == ""){
			okcoinAlert(languageJson['leaveMessage']);
			return;
		}
		try{
			var opReturn = Utils.createOP_ReturnScript(remark);
		}catch(e){
			okcoinAlert(languageJson['illegalMessage']);
			return;
		}
		
		if(opReturn.buffer.length > 40){
			okcoinAlert(languageJson['blockMessageTooLong']);
			return;
		}
	} else if(remark.length > 200){
		okcoinAlert(languageJson['messageTooLong']);
		return;
	}

	var orderAmount = parseFloat($('#orderAmount').val());
	//判断全局单位是否为mbtc,mltc
	if (isMilliUnit) {
		orderAmount = orderAmount / 1000.0;
	}
	var $selectedVault = $('#selectVault').find("option:selected");
	var coinType = $("#orderAmountType").val();
	//检查手续费
	var minerFee = parseFloat($('#minerFee').val());
	//判断全局单位是否为mbtc,mltc
	if (isMilliUnit) {
		minerFee = minerFee / 1000.0;
	}
	if(isNaN(minerFee) || (coinType == 0 && minerFee < 0.0001) || (coinType == 1 && minerFee < 0.001)){
		okcoinAlert(languageJson['noCorrectMinerFee'],null,null,languageJson['confirmbut']);
		return;
	}
	var total = (orderAmount + minerFee).toFixed(8);
	//检查余额 
	var sourceAddr = $selectedVault.val();
	if(mode == "simpleMode") {
		if(coinType == 0){
			if(total > totalBtc){
				okcoinAlert(languageJson['vaultBtcNoEnough']);
				return;
			}
		} else {
			if(total > totalLtc){
				okcoinAlert(languageJson['vaultLtcNoEnough']);
				return;
			}
		}
		$('#payFrom').hide();
		$('#changesTo').hide();
	} else {
		if(coinType == 0){
			var btc = parseFloat($selectedVault.attr("btcAmount"))
			if(total > btc){
				okcoinAlert(languageJson['vaultBtcNoEnough']);
				return;
			}
		} else {
			var ltc = parseFloat($selectedVault.attr("LtcAmount"))
			if(total > ltc){
				okcoinAlert(languageJson['vaultLtcNoEnough']);
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
			okcoinAlert(languageJson['pleaseEnter'] + typeStr + languageJson['address']);
			return;
		}
		
		if(sourceAddr == targetAddr){
			okcoinAlert(languageJson['illegalSameFromAndTargetAddress']);
			return;
		}

		$('#targetAddressOfSpan').text(targetAddr);
	}
	
	$('#quickpay').hide();
	$('#confirmDiv').show();
	$('#title').text(languageJson['confirmPay']);
	$('#advancedLink').hide();

	$('#totalCoin').text((isMilliUnit ? orderAmount*1000 : orderAmount) + (isMilliUnit ? "m" : "") + typeStr + " + " + (isMilliUnit ? minerFee*1000 : minerFee) + (isMilliUnit ? "m" : "") + typeStr +languageJson["netfee"])
}


function checkPasswordFormat(inputId, tipsId){
	if(!validatePassword(inputId, tipsId)){
		var tips = "";
		if($.trim($('#' + inputId).val()) == ""){
			tips = languageJson['entervaultpwd'];
		} else {
			tips = languageJson['onchainpwderror'];
		}
		$('#' + tipsId).text(tips).show();
		return false;
	} else {
		$('#' + tipsId).hide();
		return true;
	}
}

function clickToPay(){
	try{
		handlePayment();
	} catch(e){
		handlePayException(e)
	}
}

function handlePayException(err){
	setButtonFinish('submitBtn', languageJson['confirm']);
	$('#passwordErrorTips').text(languageJson['payFailTryAgain']).show();
	console.log("Msg of Payment Exception :" + err.toString());
}

function selectVaultsToPay(type, cAmount, coinArray){
	var vaults = [];
	var selectedVaults = [];
	var opts = $("#selectVault").find("option");
	var $opt ;
	var coinType;
	if(type == 1){
		coinType = "btcAmount";
	} else if(type == 2){
		coinType = "ltcAmount";
	}
	
	opts.each(function(){
		var v = {};
		$opt = $(this);
		if($opt.attr(coinType) > 0){
			v.vid = $opt.attr("vaultId");
			v.coin = Math.round($opt.attr(coinType) * 100000000);
			vaults.push(v);
		}
	})
	//从小到大排序
	vaults.sort(function(a, b){
		return a.coin - b.coin;
	});
	
	for(var i = 0; i < vaults.length; i++){
		cAmount = cAmount - vaults[i].coin;
		selectedVaults.push(vaults[i].vid);
		if(cAmount > 0){
			coinArray.push(vaults[i].coin);
		} else {
			coinArray.push(Math.round(cAmount + vaults[i].coin));
			break;
		}
	}
	return selectedVaults;
}

function handlePayment(){
	var inputId = "vaultPassword";
	var tipsId = "passwordErrorTips";
	
	var smsInputId = "tradePwdPhoneCode";
	var smsTip = "tradePwdPhoneCodeTip";
	
	//校验保险柜密码
	if(!checkPasswordFormat(inputId, tipsId)){
		return;
	}
	
	var selectedVault = $("#selectVault").find("option:selected");
	var multiSignMax = parseInt(selectedVault.attr("multiSignMax"));
	var $selectVaultOfChange = $('#selectVaultOfChange');
	var changesAddr = "";
	var changesVaultId = 0;
	var coinType = parseInt($("#orderAmountType").val()) + 1;
	var coinAmount = 0;
	//判断全局单位是否为mbtc,mltc
	var isMilliUnit = $('#isMilliUnit').val() == 1;
	var orderAmount = parseFloat($('#orderAmount').val());
	if (isMilliUnit) {
		orderAmount = Math.round(orderAmount * 100000);
	} else {
		orderAmount = Math.round(orderAmount * 100000000);
	}
	
	if( isNaN(orderAmount) ){
		orderAmount = 0;
	}
	
	var minerFee = parseFloat($('#minerFee').val());
	if (isMilliUnit) {
		minerFee = Math.round(minerFee * 100000);
	} else {
		minerFee = Math.round(minerFee * 100000000);
	}
	
	coinAmount = Math.round(orderAmount + minerFee);
	
	var checkSmsCode = $("#smsCodeCheck").is(":visible");
	var smsCode = $.trim($("#" + smsInputId).val());
	if(checkSmsCode && smsCode == ""){
		$("#" + smsInputId).focus();
		$("#" + smsTip).text(languageJson["numberCodeNull"]).addClass("securitylayererror")
		return;
	}
	
	var checkGoogleCode = $("#googleCodeCheck").is(":visible");
	var googleCode = $.trim($("#googleCode").val());
	if(checkGoogleCode && googleCode == ""){
		$("#googleCodeTip").focus();
		$("#googleCodeTip").text(languageJson['pleaseentergooglecode']).addClass("securitylayererror")
		return;
	}
	
	if(!checkSmsCode && !checkGoogleCode){
		okcoinAlert(languageJson['noEnableVerify'])
		return;
	}
	
	setButtonInProcess('submitBtn');
	
	var vaultId = 0;
	var vaultIdsArr;
	var coinsOfeachVaults = [];
	if(mode == "simpleMode"){
		//选择保险柜
		vaultIdsArr = selectVaultsToPay(coinType, coinAmount, coinsOfeachVaults);
	}else if(mode == "advanceMode"){
		vaultId = selectedVault.attr("vaultId");
		vaultIdsArr = [vaultId];
		coinsOfeachVaults = [coinAmount];
	}
	
	$.ajax({
		"url" : "/onchain/pay/chooseBitcoinInputs.do",
		"data" : {
			"vault_id" : vaultIdsArr.join(","),
			"coinsOfeachVaults" : coinsOfeachVaults.join(","),
			"coin_type" : coinType
		},
		success : function(data){
			if(data < 0){
				if(data == -3){
					okcoinAlert(languageJson['vaultBalanceNoEnough']);
				} else {
					okcoinAlert(languageJson['getInputTxFail'] + data);
				}
				 setButtonFinish('submitBtn', languageJson['confirmbut']);
				 return;
			}
			
			var resultInfo = eval("(" + data + ")");
			var inputs = resultInfo.tranList;
			var vaultInfos = resultInfo.vaultInfo;
			
			if(mode == "simpleMode"){
				 // 多个保险柜时，找零放到最后一个保险柜中，其它保险柜金额置0。
				 vaultId = inputs[inputs.length - 1].vaultid;
				 changesAddr = inputs[inputs.length - 1].addressTo;
				 changesVaultId = vaultId;
			 } else {
				 changesAddr = $selectVaultOfChange.val();
				 changesVaultId = $selectVaultOfChange.find("option:selected").attr("vaultId");
			 }
			
			//构建交易单，签名
			  try{
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
					
					var remark = $.trim($("#remark").val());
					var remarkToBlock = $("#remarkToBlock").attr("checked");
					if(remark != "" && remarkToBlock){
						txBuilder.addOutput(Utils.createOP_ReturnScript(remark), 0);
					}
					
					var password = $('#' + inputId).val();
					userSalt = resultInfo["userSalt"];
					password += userSalt;
					password = Bitcoin.CryptoJS.MD5(password).toString();
					
					var signatures = {};
					var maxSign = 1;
					var tran_vault_id = "";
					var vault_key = {};
					for(var i in inputs){
						var cur_vault_id = inputs[i].vaultid;
						tran_vault_id += "," + cur_vault_id;
						var privateKey = vault_key[cur_vault_id + "_key"];
						var redeemScript = vault_key[cur_vault_id + "_redeem"];
						if(privateKey == undefined || privateKey == null){
							privateKey = vaultInfos[cur_vault_id].privateKey;
							redeemScript = vaultInfos[cur_vault_id].redeemScript;
							if(redeemScript != undefined){
								 if(redeemScript != ""){
									 redeemScript = Bitcoin.Script.fromHex(redeemScript);
									 maxSign = 2;
								 } else {
									 redeemScript = undefined;
								 }
							}
							
							try{
								var decrypt = Utils.AesDecrypt(privateKey, password);
								privateKey = decrypt.toString(Bitcoin.CryptoJS.enc.Utf8);
								if(privateKey == ""){
									throw "wrongPassword"
								}
								privateKey = Bitcoin.ECKey.fromWIF(privateKey);
							}catch(e){
								$('#' + tipsId).text(languageJson['pwdVerifyFailTryAgain']).show();
							  	setButtonFinish('submitBtn', languageJson['confirm']);
						    	return;
							}

							vault_key[cur_vault_id + "_key"] = privateKey;
							vault_key[cur_vault_id + "_redeem"] = redeemScript;
						}
						
						txBuilder.sign(i, privateKey, redeemScript);
						if(redeemScript != undefined){
							signatures[i] = txBuilder.signatures[i].signatures[0].toDER().toString("hex");
						} else {
							signatures[i] = "null";
						}
					}
					 
					 var tx = null;
					 if(maxSign == 1){
						 tx = txBuilder.build();
					 } else if(maxSign >1 ) {
						 tx = txBuilder.buildIncomplete();
					 }
					 
					 var txHex = tx.toHex();
					 var txid = tx.getId();
			  }catch(e){
				  handlePayException(e);
				  return;
			  }

			  $.post(
				   "/onchain/pay/handlePayOrder.do",
				   {
					  "inputTrans" :  encodeURIComponent(JSON.stringify(inputs)),
					  "tran" :  encodeURIComponent(JSON.stringify({
						  "txid" : txid,
						  "coinType" : coinType,
						  "vaultid" : vaultId,
						  "addressTo" : targetAddress,
						  "fee" : minerFee,
						  "amount" : orderAmount,
						  "comments" : remark,
						  "changeMoney" : changes,
						  "changeVaultId" : changesVaultId
					  })),
					  "preTransaction" : txHex,
					  "partSignatures" : encodeURIComponent(JSON.stringify(signatures)),
					  "googleCode" : googleCode,
					  "phoneCode" : smsCode,
					  "vault_id" : vaultIdsArr.join(","),
					  "coinsOfeachVaults" : coinsOfeachVaults.join(",")
				  },
				  function(data){
					  var result = JSON.parse(data);
					  if(result.resultCode == 0){
						  var paramsJson = {};
						  paramsJson.targetAddr = targetAddress;
						  paramsJson.coin = orderAmount/100000000;
						  paramsJson.coinType = coinType;
						  paramsJson.id = result.objectId;
						  if(multiSignMax >1 ){
							  paramsJson.txid = result.objectCode;
						  } else {
							  paramsJson.txid = txid;
						  }

						  window.location.href="/onchain/pay/paySuccess.do?" + $.param(paramsJson);
					  } else {
						  var googleInpuId = "googleCode";
						  var googleTip = "googleCodeTip";
						  if(result.resultCode == -17||result.resultCode == -18||result.resultCode == -19){
								okcoinTipAlert(smsInputId, smsTip, result, "securitylayererror");
						  }else if(result.resultCode == -20||result.resultCode == -21||result.resultCode == -22||result.resultCode == -23){
								okcoinTipAlert(googleInpuId, googleTip, result, "securitylayererror");
						  }else{
								$('#' + tipsId).text(languageJson['payFailTryAgain']).show();
						  }
						  setButtonFinish('submitBtn', languageJson['confirm']);
					  }
					  console.log("点击确认后， 返回的信息： " + data);
				  }
			  );

		},
		"error" : function(data){
			okcoinAlert(languageJson['payFailTryAgain']);
			setButtonFinish('submitBtn', languageJson['confirm']);
		}
	});

}


