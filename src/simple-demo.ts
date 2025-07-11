import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';

// 初始化橢圓曲線加密庫
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

console.log('================================================================================');
console.log('📚 比特幣交易簽章演示程序 - 增強版');
console.log('================================================================================');

try {
    // 固定私鑰
    const privateKey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    console.log(`🔒 私鑰: ${privateKey}`);
    
    // 創建密鑰對
    const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
    const publicKey = keyPair.publicKey.toString('hex');
    console.log(`🔑 公鑰: ${publicKey}`);
    
    // 生成地址
    const { address } = bitcoin.payments.p2pkh({ 
        pubkey: keyPair.publicKey,
        network: bitcoin.networks.bitcoin 
    });
    console.log(`🏠 地址: ${address}`);
    
    console.log('\n✍️ 簽章演示:');
    
    // 創建要簽章的消息雜湊
    const message = 'Hello Bitcoin!';
    const messageHash = bitcoin.crypto.sha256(Buffer.from(message, 'utf8'));
    console.log(`📝 消息: ${message}`);
    console.log(`🔍 消息雜湊: ${messageHash.toString('hex')}`);
    
    // 執行ECDSA簽章
    // 注意：bitcoinjs-lib 的 keyPair.sign() 內部使用安全隨機數
    // 每次執行結果會不同（這是正確的安全行為）
    const signature = keyPair.sign(messageHash);
    console.log(`✒️ 簽章結果: ${signature.toString('hex')}`);
    console.log(`� 簽章長度: ${signature.length} 字節`);
    console.log(`�📝 注意: 由於使用隨機數，每次簽章結果都不同`);
    
    // 解析簽章格式
    console.log('\n🔐 簽章格式分析:');
    
    if (signature.length === 64) {
        // 64字節格式：前32字節是R值，後32字節是S值
        console.log(`📌 檢測到64字節原始格式 (r + s)`);
        
        const rValue = signature.slice(0, 32);
        const sValue = signature.slice(32, 64);
        
        console.log(`📍 R值 (前32字節): ${rValue.toString('hex')}`);
        console.log(`📍 S值 (後32字節): ${sValue.toString('hex')}`);
        console.log(`📍 V值 (恢復ID): 在比特幣中通常不使用`);
        
    } else {
        // DER格式解析
        console.log(`📌 檢測到DER編碼格式 (長度: ${signature.length}字節)`);
        
        let offset = 0;
        if (offset < signature.length) {
            const seqId = signature[offset++]; // 0x30
            const seqLength = signature[offset++];
            console.log(`📌 DER序列標識: 0x${seqId.toString(16)} (長度: ${seqLength})`);
            
            // R值
            if (offset < signature.length) {
                const rId = signature[offset++]; // 0x02
                const rLength = signature[offset++];
                const rValue = signature.slice(offset, offset + rLength);
                offset += rLength;
                console.log(`📍 R值標識: 0x${rId.toString(16)} (長度: ${rLength})`);
                console.log(`📍 R值: ${rValue.toString('hex')}`);
            }
            
            // S值
            if (offset < signature.length) {
                const sId = signature[offset++]; // 0x02
                const sLength = signature[offset++];
                const sValue = signature.slice(offset, offset + sLength);
                console.log(`📍 S值標識: 0x${sId.toString(16)} (長度: ${sLength})`);
                console.log(`📍 S值: ${sValue.toString('hex')}`);
            }
        }
    }
    
    // 驗證簽章
    const isValid = ecc.verify(messageHash, keyPair.publicKey, signature);
    console.log(`\n✅ 簽章驗證: ${isValid ? '有效' : '無效'}`);
    
    console.log('\n🎓 演示完成！');
    console.log('本程序展示了:');
    console.log('- 比特幣密鑰生成');
    console.log('- ECDSA數字簽章');
    console.log('- 原始簽章格式 (64字節 r+s)');
    console.log('- R、S值分解');
    console.log('- 簽章驗證過程');
    console.log('');
    console.log('💡 技術說明:');
    console.log('- bitcoinjs-lib 返回64字節原始格式簽章');
    console.log('- 實際比特幣網路使用DER編碼格式');
    console.log('- 每次簽章使用不同隨機數(安全特性)');
    console.log('- 如需固定結果，請參考 final-demo.js');
    
} catch (error) {
    console.error('❌ 程序執行錯誤:', error);
}
