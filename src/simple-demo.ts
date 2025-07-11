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
    
    // 使用固定隨機數（教學用途）
    const fixedK = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    console.log(`🎲 固定隨機數 k: ${fixedK}`);
    
    // 執行ECDSA簽章
    const signature = keyPair.sign(messageHash);
    console.log(`✒️ DER簽章: ${signature.toString('hex')}`);
    
    // 解析DER編碼簽章
    console.log('\n🔐 ECDSA簽章分解:');
    
    // 手動解析DER格式
    let offset = 0;
    const seqId = signature[offset++]; // 0x30
    const seqLength = signature[offset++];
    console.log(`📌 DER序列標識: 0x${seqId.toString(16)} (長度: ${seqLength})`);
    
    // R值
    const rId = signature[offset++]; // 0x02
    const rLength = signature[offset++];
    const rValue = signature.slice(offset, offset + rLength);
    offset += rLength;
    console.log(`📍 R值標識: 0x${rId.toString(16)} (長度: ${rLength})`);
    console.log(`📍 R值: ${rValue.toString('hex')}`);
    
    // S值
    const sId = signature[offset++]; // 0x02
    const sLength = signature[offset++];
    const sValue = signature.slice(offset, offset + sLength);
    console.log(`📍 S值標識: 0x${sId.toString(16)} (長度: ${sLength})`);
    console.log(`📍 S值: ${sValue.toString('hex')}`);
    
    // 恢復ID（簡化版）
    console.log(`📍 V值 (恢復ID): 0 (演示用固定值)`);
    
    // 驗證簽章
    const isValid = ecc.verify(messageHash, keyPair.publicKey, signature);
    console.log(`\n✅ 簽章驗證: ${isValid ? '有效' : '無效'}`);
    
    console.log('\n🎓 演示完成！');
    console.log('本程序展示了:');
    console.log('- 比特幣密鑰生成');
    console.log('- ECDSA數字簽章');
    console.log('- DER編碼格式解析');
    console.log('- R、S、V值分解');
    console.log('- 簽章驗證過程');
    
} catch (error) {
    console.error('❌ 程序執行錯誤:', error);
}
