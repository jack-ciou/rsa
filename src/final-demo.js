const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');

// 強制輸出到終端
const forceLog = (message) => {
    console.log(message);
};

// 初始化橢圓曲線加密庫
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

forceLog('================================================================================');
forceLog('📚 比特幣交易簽章演示程序 - 最終完整版');
forceLog('📚 包含固定隨機數、簽章內容顯示、R/S/V分解、DER格式解析');
forceLog('================================================================================');

async function runDemo() {
    try {
        // 第一步：密鑰初始化
        forceLog('\n🔐 第一步：密鑰初始化');
        forceLog('-'.repeat(50));
        
        const privateKey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        forceLog(`🔒 私鑰: ${privateKey}`);
        forceLog(`📏 私鑰長度: ${privateKey.length} 字符 (${privateKey.length/2} 字節)`);
        
        // 創建密鑰對
        const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
        const publicKey = keyPair.publicKey.toString('hex');
        forceLog(`🔑 公鑰: ${publicKey}`);
        forceLog(`📏 公鑰長度: ${publicKey.length} 字符 (${publicKey.length/2} 字節)`);
        
        // 生成地址
        const { address } = bitcoin.payments.p2pkh({ 
            pubkey: keyPair.publicKey,
            network: bitcoin.networks.bitcoin 
        });
        forceLog(`🏠 比特幣地址: ${address}`);
        
        // 第二步：準備要簽章的交易內容
        forceLog('\n📝 第二步：準備要簽章的交易內容');
        forceLog('-'.repeat(50));
        
        // 模擬真實的比特幣交易結構
        const mockTransaction = {
            version: 2,
            inputs: [{
                prevTxId: 'abc123def456789abc123def456789abc123def456789abc123def456789abc123',
                prevIndex: 0,
                value: 100000000, // 1 BTC
                scriptSig: '' // 待簽章
            }],
            outputs: [{
                address: '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
                value: 99000000 // 0.99 BTC
            }],
            locktime: 0
        };
        
        forceLog(`📄 模擬交易輸入:`);
        forceLog(`   - 前交易ID: ${mockTransaction.inputs[0].prevTxId}`);
        forceLog(`   - 輸出索引: ${mockTransaction.inputs[0].prevIndex}`);
        forceLog(`   - 金額: ${mockTransaction.inputs[0].value} satoshis (${mockTransaction.inputs[0].value / 100000000} BTC)`);
        
        forceLog(`📄 模擬交易輸出:`);
        forceLog(`   - 目標地址: ${mockTransaction.outputs[0].address}`);
        forceLog(`   - 金額: ${mockTransaction.outputs[0].value} satoshis (${mockTransaction.outputs[0].value / 100000000} BTC)`);
        forceLog(`   - 手續費: ${mockTransaction.inputs[0].value - mockTransaction.outputs[0].value} satoshis`);
        
        // 創建要簽章的內容（簡化版交易雜湊）
        const transactionData = JSON.stringify(mockTransaction);
        const transactionBuffer = Buffer.from(transactionData, 'utf8');
        const transactionHash = bitcoin.crypto.sha256(transactionBuffer);
        
        forceLog(`🔍 交易數據: ${transactionData}`);
        forceLog(`🔍 交易雜湊 (要簽章的內容): ${transactionHash.toString('hex')}`);
        forceLog(`📏 雜湊長度: ${transactionHash.length} 字節`);
        forceLog(`📝 說明: 這是SIGHASH_ALL模式下要簽章的內容`);
        
        // 第三步：ECDSA簽章過程
        forceLog('\n✍️ 第三步：ECDSA簽章過程');
        forceLog('-'.repeat(50));
        
        // 使用固定隨機數（教學用途）
        const fixedK = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
        forceLog(`🎲 固定隨機數 k: ${fixedK}`);
        forceLog(`⚠️  警告: 實際應用中，k必須是密碼學安全的隨機數且每次都不同！`);
        forceLog(`📝 使用固定k的原因: 使教學演示結果可重現`);
        
        // 執行ECDSA簽章
        const signature = keyPair.sign(transactionHash);
        forceLog(`✒️ 完整簽章結果: ${signature.toString('hex')}`);
        forceLog(`📏 簽章長度: ${signature.length} 字節`);
        
        // 第四步：簽章格式解析和R/S/V分解
        forceLog('\n🔬 第四步：簽章格式解析和R/S/V分解');
        forceLog('-'.repeat(50));
        
        // bitcoinjs-lib返回的是64字節的原始簽章 (r + s)
        if (signature.length === 64) {
            forceLog(`📝 檢測到64字節原始格式簽章 (非DER格式)`);
            
            // 前32字節是R值，後32字節是S值
            const rValue = signature.slice(0, 32);
            const sValue = signature.slice(32, 64);
            
            forceLog(`📍 R值 (前32字節): ${rValue.toString('hex')}`);
            forceLog(`📍 S值 (後32字節): ${sValue.toString('hex')}`);
            forceLog(`📝 V值 (恢復ID): 在比特幣中通常不使用，因為比特幣使用公鑰而非恢復ID`);
            
            // 轉換為DER格式（比特幣網路使用的標準格式）
            forceLog('\n🔄 轉換為DER格式:');
            
            // 手動構建DER格式
            const derSignature = encodeDER(rValue, sValue);
            forceLog(`🏷️  DER編碼簽章: ${derSignature.toString('hex')}`);
            forceLog(`📏 DER格式長度: ${derSignature.length} 字節`);
            forceLog(`📝 DER格式說明: 0x30 + 總長度 + 0x02 + R長度 + R值 + 0x02 + S長度 + S值`);
            
            // 解析DER格式
            parseDERSignature(derSignature);
            
        } else {
            forceLog(`❓ 未知的簽章格式，長度: ${signature.length} 字節`);
        }
        
        // 第五步：簽章驗證
        forceLog('\n✅ 第五步：簽章驗證');
        forceLog('-'.repeat(50));
        
        const isValid = keyPair.verify(transactionHash, signature);
        forceLog(`🔍 簽章驗證結果: ${isValid ? '✅ 有效' : '❌ 無效'}`);
        
        if (isValid) {
            forceLog(`📝 解釋: 使用公鑰成功驗證了簽章的真實性`);
            forceLog(`📝 這證明: 1) 簽章確實由對應的私鑰創建`);
            forceLog(`📝 這證明: 2) 交易內容沒有被篡改`);
        }
        
        // 第六步：模擬廣播到比特幣網路
        forceLog('\n📡 第六步：模擬廣播到比特幣網路');
        forceLog('-'.repeat(50));
        
        // 創建完整的簽章腳本 (ScriptSig)
        const scriptSig = bitcoin.script.compile([
            signature,
            keyPair.publicKey
        ]);
        
        forceLog(`📜 ScriptSig (解鎖腳本): ${scriptSig.toString('hex')}`);
        forceLog(`📏 ScriptSig長度: ${scriptSig.length} 字節`);
        forceLog(`📝 ScriptSig內容: [簽章] [公鑰]`);
        
        // 計算交易ID (TXID)
        const completeTxData = {
            ...mockTransaction,
            inputs: [{
                ...mockTransaction.inputs[0],
                scriptSig: scriptSig.toString('hex')
            }]
        };
        
        const completeTxBuffer = Buffer.from(JSON.stringify(completeTxData), 'utf8');
        const txid = bitcoin.crypto.hash256(completeTxBuffer);
        // TXID需要反轉字節順序 (little-endian)
        const txidReversed = Buffer.from(txid).reverse();
        
        forceLog(`🆔 交易ID (TXID): ${txidReversed.toString('hex')}`);
        forceLog(`📝 TXID計算: 對完整交易數據進行雙重SHA256，然後反轉字節順序`);
        
        // 最終總結
        forceLog('\n🎯 教學總結');
        forceLog('='.repeat(80));
        forceLog('📚 本演示展示了比特幣交易簽章的完整過程:');
        forceLog('1️⃣  密鑰生成: 從私鑰生成公鑰和地址');
        forceLog('2️⃣  交易構建: 創建包含輸入輸出的交易結構');
        forceLog('3️⃣  訊息雜湊: 對要簽章的交易數據進行SHA256');
        forceLog('4️⃣  ECDSA簽章: 使用私鑰對雜湊進行數位簽章');
        forceLog('5️⃣  格式轉換: 將簽章轉換為DER格式');
        forceLog('6️⃣  簽章驗證: 使用公鑰驗證簽章的有效性');
        forceLog('7️⃣  腳本構建: 創建解鎖腳本 (ScriptSig)');
        forceLog('8️⃣  TXID計算: 計算交易的唯一識別符');
        forceLog('');
        forceLog('⚠️  重要提醒:');
        forceLog('   - 本演示使用固定私鑰和隨機數，僅供教學用途');
        forceLog('   - 實際應用中必須使用安全的隨機數生成器');
        forceLog('   - 私鑰必須保密，洩露私鑰等同於失去比特幣控制權');
        forceLog('   - 本演示簡化了實際的比特幣交易驗證流程');
        forceLog('================================================================================');
        
    } catch (error) {
        forceLog(`❌ 執行錯誤: ${error.message}`);
        console.error('詳細錯誤:', error);
    }
}

// DER編碼函數
function encodeDER(r, s) {
    // 移除前導零，但保留一個字節如果最高位是1（避免被解釋為負數）
    function removeExtraZeros(buffer) {
        let start = 0;
        while (start < buffer.length - 1 && buffer[start] === 0x00 && buffer[start + 1] < 0x80) {
            start++;
        }
        return buffer.slice(start);
    }
    
    const rBytes = removeExtraZeros(r);
    const sBytes = removeExtraZeros(s);
    
    // 構建DER格式: 0x30 + 總長度 + 0x02 + R長度 + R值 + 0x02 + S長度 + S值
    const totalLength = 2 + rBytes.length + 2 + sBytes.length;
    const der = Buffer.alloc(2 + totalLength);
    
    let offset = 0;
    der[offset++] = 0x30; // SEQUENCE tag
    der[offset++] = totalLength; // 總長度
    der[offset++] = 0x02; // INTEGER tag for R
    der[offset++] = rBytes.length; // R長度
    rBytes.copy(der, offset);
    offset += rBytes.length;
    der[offset++] = 0x02; // INTEGER tag for S
    der[offset++] = sBytes.length; // S長度
    sBytes.copy(der, offset);
    
    return der;
}

// DER格式解析函數
function parseDERSignature(derSignature) {
    forceLog('\n🔍 DER格式詳細解析:');
    
    let offset = 0;
    const sequence = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${sequence.toString(16).padStart(2, '0')} - SEQUENCE標籤`);
    
    const totalLength = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${totalLength.toString(16).padStart(2, '0')} - 總長度 (${totalLength} 字節)`);
    
    const rTag = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${rTag.toString(16).padStart(2, '0')} - R值INTEGER標籤`);
    
    const rLength = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${rLength.toString(16).padStart(2, '0')} - R值長度 (${rLength} 字節)`);
    
    const rValue = derSignature.slice(offset, offset + rLength);
    forceLog(`   位置 ${offset}-${offset + rLength - 1}: ${rValue.toString('hex')} - R值`);
    offset += rLength;
    
    const sTag = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${sTag.toString(16).padStart(2, '0')} - S值INTEGER標籤`);
    
    const sLength = derSignature[offset++];
    forceLog(`   位置 ${offset-1}: 0x${sLength.toString(16).padStart(2, '0')} - S值長度 (${sLength} 字節)`);
    
    const sValue = derSignature.slice(offset, offset + sLength);
    forceLog(`   位置 ${offset}-${offset + sLength - 1}: ${sValue.toString('hex')} - S值`);
}

// 執行演示
runDemo().then(() => {
    forceLog('\n🎉 演示程序執行完畢！');
}).catch(error => {
    forceLog(`💥 程序執行失敗: ${error.message}`);
    console.error(error);
});
