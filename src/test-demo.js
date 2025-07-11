console.log('='.repeat(80));
console.log('📚 比特幣簽章演示 - 測試版本');
console.log('='.repeat(80));

// 測試基本輸出
console.log('✅ 程序開始執行');

try {
    // 測試依賴載入
    console.log('📦 載入依賴...');
    const bitcoin = require('bitcoinjs-lib');
    const ecc = require('tiny-secp256k1');
    const { ECPairFactory } = require('ecpair');
    
    console.log('✅ 依賴載入成功');
    
    // 初始化
    console.log('🔧 初始化加密庫...');
    bitcoin.initEccLib(ecc);
    const ECPair = ECPairFactory(ecc);
    console.log('✅ 初始化完成');
    
    // 創建密鑰
    console.log('🔐 創建密鑰對...');
    const privateKey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    const keyPair = ECPair.fromPrivateKey(Buffer.from(privateKey, 'hex'));
    const publicKey = keyPair.publicKey.toString('hex');
    
    console.log(`🔒 私鑰: ${privateKey}`);
    console.log(`🔑 公鑰: ${publicKey}`);
    
    // 生成地址
    console.log('🏠 生成地址...');
    const { address } = bitcoin.payments.p2pkh({ 
        pubkey: keyPair.publicKey,
        network: bitcoin.networks.bitcoin 
    });
    console.log(`🏠 地址: ${address}`);
    
    // 簽章演示
    console.log('✍️ 執行簽章...');
    const message = 'Hello Bitcoin!';
    const messageHash = bitcoin.crypto.sha256(Buffer.from(message, 'utf8'));
    const signature = keyPair.sign(messageHash);
    
    console.log(`📝 消息: ${message}`);
    console.log(`🔍 雜湊: ${messageHash.toString('hex')}`);
    console.log(`✒️ 簽章: ${signature.toString('hex')}`);
    console.log(`📏 簽章長度: ${signature.length} 字節`);
    
    // R/S值分解
    if (signature.length === 64) {
        const rValue = signature.slice(0, 32);
        const sValue = signature.slice(32, 64);
        
        console.log('\n🔐 R/S/V 分解:');
        console.log(`📍 R值: ${rValue.toString('hex')}`);
        console.log(`📍 S值: ${sValue.toString('hex')}`);
        console.log(`📍 V值: 0 (恢復ID)`);
    }
    
    // 驗證簽章
    console.log('\n✅ 驗證簽章...');
    const isValid = ecc.verify(messageHash, keyPair.publicKey, signature);
    console.log(`🔍 驗證結果: ${isValid ? '有效' : '無效'}`);
    
    console.log('\n🎉 程序執行完成！');
    
} catch (error) {
    console.error('❌ 錯誤:', error);
    console.error('堆疊:', error.stack);
}

console.log('📋 程序結束');
