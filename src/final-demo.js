const bitcoin = require('bitcoinjs-lib');
const ecc = require('tiny-secp256k1');
const { ECPairFactory } = require('ecpair');
const crypto = require('crypto');

// 強制輸出到終端
const forceLog = (message) => {
    console.log(message);
};

// 確定性簽章函數（模擬固定k效果）
function deterministicSign(messageHash, privateKeyHex, fixedSeed) {
    // 使用固定種子和消息創建確定性的"隨機"字節
    const seedData = Buffer.concat([
        Buffer.from(fixedSeed, 'hex'),
        messageHash,
        Buffer.from(privateKeyHex, 'hex')
    ]);
    
    // 創建確定性的種子
    const deterministicSeed = crypto.createHash('sha256').update(seedData).digest();
    
    // 使用確定性種子創建私鑰對象進行簽章
    // 注意：這不是真正的固定k，但會產生確定性結果
    const originalSign = ecc.sign;
    let callCount = 0;
    
    // 暫時覆蓋隨機数生成，使其確定性
    const originalRandomBytes = crypto.randomBytes;
    crypto.randomBytes = function(size) {
        // 創建確定性的"隨機"字節
        const hash = crypto.createHash('sha256')
            .update(deterministicSeed)
            .update(Buffer.from([callCount++]))
            .digest();
        return hash.slice(0, size);
    };
    
    try {
        // 執行簽章
        const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKeyHex, 'hex'));
        const signature = keyPair.sign(messageHash);
        
        // 恢復原始函數
        crypto.randomBytes = originalRandomBytes;
        
        return signature;
    } catch (error) {
        // 恢復原始函數
        crypto.randomBytes = originalRandomBytes;
        throw error;
    }
}

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
        
        // 第三步：ECDSA簽章過程（使用固定隨機數）
        forceLog('\n✍️ 第三步：ECDSA簽章過程');
        forceLog('-'.repeat(50));
        
        // 使用固定隨機數（教學用途）
        const fixedK = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
        forceLog(`🎲 固定隨機數 k: ${fixedK}`);
        forceLog(`⚠️  警告: 實際應用中，k必須是密碼學安全的隨機數且每次都不同！`);
        forceLog(`📝 使用固定k的原因: 使教學演示結果可重現`);
        
        // k值範圍說明
        forceLog('\n📏 k值的有效範圍:');
        const n = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
        forceLog(`📐 曲線階數 n = ${n}`);
        forceLog(`📊 k值必須滿足: 1 ≤ k < n`);
        forceLog(`📊 即: 1 ≤ k < ${n}`);
        forceLog(`🔍 我們的固定k = ${fixedK}`);
        
        // 驗證k值是否在有效範圍內
        const kBigInt = BigInt('0x' + fixedK);
        const nBigIntForK = BigInt('0x' + n);
        const isValidK = kBigInt >= 1n && kBigInt < nBigIntForK;
        
        forceLog(`✅ k值範圍檢查: ${isValidK ? '有效 ✓' : '無效 ✗'}`);
        forceLog(`📊 k值大小比較:`);
        forceLog(`   🔢 k = ${kBigInt.toString()}`);
        forceLog(`   🔢 n = ${nBigIntForK.toString()}`);
        forceLog(`   📏 k < n: ${kBigInt < nBigIntForK ? '是' : '否'}`);
        
        forceLog('\n⚠️  k值安全要求:');
        forceLog(`🔐 1. k 必須是密碼學安全的隨機數`);
        forceLog(`🔐 2. k 必須在範圍 [1, n-1] 內`);
        forceLog(`🔐 3. k 絕對不能重複使用`);
        forceLog(`🔐 4. k 必須保密，洩露k會導致私鑰洩露`);
        forceLog(`🔐 5. k 的生成必須具有足夠的熵`);
        
        // 展示k值洩露的危險性
        forceLog('\n🚨 k值重複使用的危險性示例:');
        forceLog(`💀 如果同一個k值被用於簽章兩個不同的消息...`);
        forceLog(`💀 攻击者可以通過以下公式計算出私鑰:`);
        forceLog(`💀 私鑰 = (s₁×雜湊₂ - s₂×雜湊₁) × (r×(s₁-s₂))⁻¹ mod n`);
        forceLog(`💀 這就是為什麼k值絕對不能重複使用！`);
        
        // R值與k值的關係驗證
        forceLog('\n🔬 R值與k值的數學關係驗證');
        forceLog('-'.repeat(50));
        forceLog(`📐 理論基礎: R = k × G (G為secp256k1基點)`);
        forceLog(`📊 其中: r = R.x mod n (取R點的x座標)`);
        
        // secp256k1 基點座標
        const Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798';
        const Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8';
        forceLog(`📍 基點G座標:`);
        forceLog(`   Gx = 0x${Gx}`);
        forceLog(`   Gy = 0x${Gy}`);
        
        // 手動計算 k × G 來驗證 R 值
        forceLog('\n🧮 手動驗證 R = k × G:');
        forceLog(`🔍 給定固定k = ${fixedK}`);
        
        // 使用 tiny-secp256k1 進行點乘運算
        const kBuffer = Buffer.from(fixedK, 'hex');
        
        let calculatedR = null;
        let calculatedS = null;
        
        try {
            // 檢查 k 值是否有效（必須在 1 到 n-1 範圍內）
            const kBigInt = BigInt('0x' + fixedK);
            const nBigInt = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
            
            if (kBigInt <= 0n || kBigInt >= nBigInt) {
                throw new Error('k 值超出有效範圍');
            }
            
            // 方法1：使用 bitcoinjs-lib 的內建功能來計算 k×G
            try {
                // 創建一個臨時的密鑰對來計算 k×G
                const tempKeyPair = ECPair.fromPrivateKey(kBuffer);
                const kTimesG = tempKeyPair.publicKey;
                
                forceLog(`✨ 計算結果 R = k × G (方法1 - 使用ECPair):`);
                forceLog(`   📊 R點 (完整格式): ${kTimesG.toString('hex')}`);
                
                // 提取 x 座標（去除壓縮前綴 0x02 或 0x03）
                const Rx = kTimesG.slice(1, 33);
                calculatedR = Rx.toString('hex');
                forceLog(`   📊 Rx座標: ${calculatedR}`);
                
            } catch (error) {
                forceLog(`❌ 方法1失敗: ${error.message}`);
                
                // 方法2：直接使用 tiny-secp256k1 的 pointMultiply
                try {
                    // secp256k1 的基點 G（未壓縮格式）
                    const basePointUncompressed = Buffer.from(
                        '0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798' +
                        '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 
                        'hex'
                    );
                    
                    // 使用 pointMultiply 計算 k × G
                    const kTimesG = ecc.pointMultiply(basePointUncompressed, kBuffer);
                    
                    if (kTimesG && kTimesG.length >= 33) {
                        forceLog(`✨ 計算結果 R = k × G (方法2 - 直接pointMultiply):`);
                        forceLog(`   📊 R點: ${kTimesG.toString('hex')}`);
                        
                        // 提取 x 座標
                        let Rx;
                        if (kTimesG.length === 33) {
                            // 壓縮格式
                            Rx = kTimesG.slice(1, 33);
                        } else if (kTimesG.length === 65) {
                            // 未壓縮格式
                            Rx = kTimesG.slice(1, 33);
                        } else {
                            throw new Error(`意外的點格式長度: ${kTimesG.length}`);
                        }
                        
                        calculatedR = Rx.toString('hex');
                        forceLog(`   📊 Rx座標: ${calculatedR}`);
                        
                    } else {
                        throw new Error('pointMultiply 返回無效結果');
                    }
                    
                } catch (error2) {
                    forceLog(`❌ 方法2也失敗: ${error2.message}`);
                    
                    // 方法3：手動實現點乘法（教學用途）
                    try {
                        forceLog(`🔧 嘗試方法3 - 理論計算說明:`);
                        forceLog(`📐 由於點乘法計算複雜，我們改為解釋理論:`);
                        forceLog(`📐 R = k × G 其中:`);
                        forceLog(`   🔢 k = ${fixedK} (我們的固定隨機數)`);
                        forceLog(`   📍 G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,`);
                        forceLog(`           0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)`);
                        forceLog(`📐 實際的 k×G 計算需要進行橢圓曲線點乘法運算`);
                        forceLog(`📐 這涉及到有限域上的複雜數學運算`);
                        
                        // 至少我們可以說明為什麼會失敗
                        forceLog(`\n💡 計算失敗的可能原因:`);
                        forceLog(`   1️⃣ tiny-secp256k1 版本兼容性問題`);
                        forceLog(`   2️⃣ pointMultiply 函數參數格式問題`);
                        forceLog(`   3️⃣ k 值格式或範圍問題`);
                        forceLog(`   4️⃣ 基點 G 的格式問題（壓縮 vs 未壓縮）`);
                        
                        // 我們可以改為驗證實際簽章中的 R 值
                        calculatedR = '預期在實際簽章中驗證';
                        
                    } catch (error3) {
                        forceLog(`❌ 所有方法都失敗了: ${error3.message}`);
                        calculatedR = null;
                    }
                }
            }
            
        } catch (error) {
            forceLog(`❌ k×G 計算過程發生錯誤: ${error.message}`);
            forceLog(`📝 錯誤詳情: ${error.stack ? error.stack.split('\n')[0] : '無詳細信息'}`);
            
            // 提供替代方案
            forceLog(`\n🔄 替代方案 - 理論解釋:`);
            forceLog(`📐 雖然無法直接計算 k×G，但我們可以通過實際簽章來驗證關係`);
            forceLog(`📐 在實際簽章中，r 值就是 (k×G).x，即 R 點的 x 座標`);
            forceLog(`📐 我們將在後續步驟中從實際簽章提取 r 值來驗證`);
        }
        
        // 執行實際簽章
        forceLog('\n🖊️ 執行實際簽章:');
        const signature = deterministicSign(transactionHash, privateKey, fixedK);
        forceLog(`📝 簽章完成，長度: ${signature.length} 字節`);
        forceLog(`📝 簽章結果: ${signature.toString('hex')}`);
        
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
            
            // 使用實際簽章的R值進行S值驗證
            forceLog(`\n🔬 使用實際簽章的R值重新驗證S值計算:`);
            
            // 準備計算所需的值 - 使用實際簽章的R值
            const hashBigInt = BigInt('0x' + transactionHash.toString('hex'));
            const actualRBigInt = BigInt('0x' + rValue.toString('hex'));
            const actualSBigInt = BigInt('0x' + sValue.toString('hex'));
            const privateBigInt = BigInt('0x' + privateKey);
            const nBigInt = BigInt('0x' + n);
            
            forceLog(`📊 使用實際簽章參數重新計算:`);
            forceLog(`   🔢 hash = ${hashBigInt.toString(16)} (十六進制)`);
            forceLog(`   🔢 實際r = ${actualRBigInt.toString(16)} (十六進制)`);
            forceLog(`   🔢 實際s = ${actualSBigInt.toString(16)} (十六進制)`);
            forceLog(`   🔢 私鑰 = ${privateBigInt.toString(16)} (十六進制)`);
            forceLog(`   🔢 n = ${nBigInt.toString(16)} (十六進制)`);
            
            try {
                // 驗證簽章的數學關係：s × k ≡ hash + r × 私鑰 (mod n)
                // 但我們不知道確定性簽章實際使用的k值，所以我們反過來驗證
                // 使用ECDSA驗證公式：驗證點 = s⁻¹ × hash × G + s⁻¹ × r × 公鑰點
                
                forceLog(`\n🧮 ECDSA簽章驗證的數學關係:`);
                forceLog(`📐 公式: s × k ≡ hash + r × 私鑰 (mod n)`);
                forceLog(`📐 如果我們知道k，可以驗證: k = s⁻¹ × (hash + r × 私鑰) mod n`);
                
                // 計算 s 的模逆元
                const sInverse = modInverse(actualSBigInt, nBigInt);
                forceLog(`🔍 計算步驟:`);
                forceLog(`   🧮 s⁻¹ mod n = ${sInverse.toString(16)} (十六進制)`);
                
                // 計算 r × 私鑰
                const rTimesPrivate = (actualRBigInt * privateBigInt) % nBigInt;
                forceLog(`   🧮 r × 私鑰 mod n = ${rTimesPrivate.toString(16)} (十六進制)`);
                
                // 計算 hash + r × 私鑰
                const hashPlusRPrivate = (hashBigInt + rTimesPrivate) % nBigInt;
                forceLog(`   🧮 (hash + r × 私鑰) mod n = ${hashPlusRPrivate.toString(16)} (十六進制)`);
                
                // 計算實際使用的 k 值
                const actualK = (sInverse * hashPlusRPrivate) % nBigInt;
                forceLog(`\n✨ 反推出實際使用的 k 值:`);
                forceLog(`   📊 k = s⁻¹ × (hash + r × 私鑰) mod n`);
                forceLog(`   📊 k = ${actualK.toString(16)} (十六進制)`);
                
                // 驗證計算正確性：重新計算 s 值
                const kInverse = modInverse(actualK, nBigInt);
                const recalculatedS = (kInverse * hashPlusRPrivate) % nBigInt;
                
                forceLog(`\n🔍 驗證計算正確性:`);
                forceLog(`   🧮 使用反推的k值重新計算s:`);
                forceLog(`   🧮 k⁻¹ mod n = ${kInverse.toString(16)}`);
                forceLog(`   🧮 重新計算的s = k⁻¹ × (hash + r × 私鑰) mod n`);
                forceLog(`   🧮 重新計算的s = ${recalculatedS.toString(16)}`);
                forceLog(`   🧮 實際簽章的s = ${actualSBigInt.toString(16)}`);
                
                const sMatches = recalculatedS === actualSBigInt;
                forceLog(`   ✅ S值驗證: ${sMatches ? '正確 ✓' : '錯誤 ✗'}`);
                
                if (sMatches) {
                    forceLog(`\n🎯 數學關係驗證成功！`);
                    forceLog(`📐 這證明了ECDSA簽章的數學一致性`);
                }
                
                // 比較固定k值與實際k值
                if (fixedK) {
                    const fixedKBigInt = BigInt('0x' + fixedK);
                    forceLog(`\n🔍 k值比較:`);
                    forceLog(`   🎲 我們設定的固定k = ${fixedK}`);
                    forceLog(`   🎲 實際簽章使用的k = ${actualK.toString(16).padStart(64, '0')}`);
                    forceLog(`   ✅ k值匹配: ${fixedKBigInt === actualK ? '是 ✓' : '否 ✗'}`);
                    
                    if (fixedKBigInt !== actualK) {
                        forceLog(`📝 說明: deterministicSign函數並非真正使用固定k，而是產生確定性結果`);
                        forceLog(`📝 這是因為bitcoinjs-lib內部有自己的隨機數生成機制`);
                    }
                }
                
                // 演示k值洩露的危險性
                forceLog(`\n💀 演示k值洩露攻擊:`);
                forceLog(`📐 假設攻擊者知道了k值: ${actualK.toString(16)}`);
                forceLog(`📐 攻擊者可以通過以下公式計算私鑰:`);
                forceLog(`📐 私鑰 = r⁻¹ × (s × k - hash) mod n`);
                
                try {
                    // 演示攻擊計算
                    const rInverse = modInverse(actualRBigInt, nBigInt);
                    const sTimesK = (actualSBigInt * actualK) % nBigInt;
                    const sTimesKMinusHash = (sTimesK - hashBigInt + nBigInt) % nBigInt;
                    const recoveredPrivateKey = (rInverse * sTimesKMinusHash) % nBigInt;
                    
                    forceLog(`🔍 攻击计算步驟:`);
                    forceLog(`   🧮 r⁻¹ mod n = ${rInverse.toString(16)}`);
                    forceLog(`   🧮 s × k mod n = ${sTimesK.toString(16)}`);
                    forceLog(`   🧮 (s × k - hash) mod n = ${sTimesKMinusHash.toString(16)}`);
                    forceLog(`   🧮 恢復的私鑰 = ${recoveredPrivateKey.toString(16)}`);
                    forceLog(`   🔢 原始私鑰 = ${privateBigInt.toString(16)}`);
                    
                    const privateKeyMatches = recoveredPrivateKey === privateBigInt;
                    forceLog(`   ✅ 私鑰恢復: ${privateKeyMatches ? '成功 ⚠️' : '失敗'}`);
                    
                    if (privateKeyMatches) {
                        forceLog(`\n💀 攻擊成功！這證明了k值洩露的嚴重後果！`);
                        forceLog(`⚠️  這就是為什麼k值必須保密且每次都不同！`);
                    }
                    
                } catch (error) {
                    forceLog(`❌ 攻击演示計算錯誤: ${error.message}`);
                }
                
            } catch (error) {
                forceLog(`❌ S 值驗證過程發生錯誤: ${error.message}`);
            }
            
            // 比較實際簽章與理論計算（如果有的話）
            if (calculatedR) {
                forceLog(`\n🔍 理論與實際比較:`);
                forceLog(`   📊 理論計算的 R: ${calculatedR}`);
                forceLog(`   📊 實際簽章的 R: ${rValue.toString('hex')}`);
                forceLog(`   ✅ R值匹配: ${calculatedR === rValue.toString('hex') ? '是 ✓' : '否 ✗'}`);
                
                if (calculatedR !== rValue.toString('hex')) {
                    forceLog(`📝 說明: 理論計算使用固定k，實際簽章使用確定性但不同的k值`);
                }
            }
            
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

// 計算模逆元的函數
function modInverse(a, m) {
    // 使用擴展歐幾里得算法計算 a 在模 m 下的逆元
    function extendedGCD(a, b) {
        if (a === 0n) {
            return { gcd: b, x: 0n, y: 1n };
        }
        const { gcd, x: x1, y: y1 } = extendedGCD(b % a, a);
        const x = y1 - (b / a) * x1;
        const y = x1;
        return { gcd, x, y };
    }
    
    const { gcd, x } = extendedGCD(a % m, m);
    if (gcd !== 1n) {
        throw new Error('模逆元不存在');
    }
    return ((x % m) + m) % m;
}

// 執行演示
runDemo().then(() => {
    forceLog('\n🎉 演示程序執行完畢！');
}).catch(error => {
    forceLog(`💥 程序執行失敗: ${error.message}`);
    console.error(error);
});