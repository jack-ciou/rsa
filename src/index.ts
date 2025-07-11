import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';

// 初始化橢圓曲線加密庫
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);

/**
 * BTC交易簽章演示程序
 * 作者：加密學教授
 * 功能：展示完整的比特幣交易創建和簽章過程
 */
class BitcoinTransactionDemo {
    private privateKey: string;
    private keyPair: any;
    private address: string = '';
    private publicKey: string = '';

    constructor() {
        // 1. 使用固定的私鑰（32字節的十六進制字符串）
        this.privateKey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
        console.log('='.repeat(80));
        console.log('📚 比特幣交易簽章演示程序');
        console.log('='.repeat(80));
        
        this.initializeKeys();
    }

    /**
     * 初始化密鑰對和地址
     */
    private initializeKeys(): void {
        console.log('\n🔐 第一步：密鑰初始化');
        console.log('-'.repeat(50));
        
        // 從私鑰創建密鑰對
        const privateKeyBuffer = Buffer.from(this.privateKey, 'hex');
        this.keyPair = ECPair.fromPrivateKey(privateKeyBuffer);
        
        // 獲取公鑰
        this.publicKey = this.keyPair.publicKey.toString('hex');
        
        // 生成P2PKH地址（Legacy地址）
        const { address } = bitcoin.payments.p2pkh({ 
            pubkey: this.keyPair.publicKey,
            network: bitcoin.networks.bitcoin // mainnet
        });
        this.address = address!;

        // 顯示密鑰信息
        console.log(`🔒 私鑰 (Private Key): ${this.privateKey}`);
        console.log(`🔑 公鑰 (Public Key): ${this.publicKey}`);
        console.log(`🏠 地址 (Address): ${this.address}`);
        console.log(`📏 私鑰長度: ${this.privateKey.length} 字符 (${this.privateKey.length/2} 字節)`);
        console.log(`📏 公鑰長度: ${this.publicKey.length} 字符 (${this.publicKey.length/2} 字節)`);
    }

    /**
     * 創建並簽章比特幣交易
     */
    public createAndSignTransaction(): void {
        console.log('\n💰 第二步：創建比特幣交易');
        console.log('-'.repeat(50));

        // 模擬的UTXO輸入（在實際應用中需要從區塊鏈查詢）
        let prevTxId = 'abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab';
        const prevTxIndex = 0;
        const inputAmount = 100000000; // 1 BTC in satoshis
        
        // 首先創建前一個交易並獲取其實際雜湊
        const prevTxHex = this.createMockPrevTxHex(prevTxId, inputAmount);
        const prevTxBuffer = Buffer.from(prevTxHex, 'hex');
        const hash1 = bitcoin.crypto.sha256(prevTxBuffer);
        const hash2 = bitcoin.crypto.sha256(hash1);
        const actualPrevTxId = hash2.reverse().toString('hex');
        prevTxId = actualPrevTxId; // 使用實際計算出的ID
        
        console.log(`📥 輸入交易ID: ${prevTxId}`);
        console.log(`📍 輸入索引: ${prevTxIndex}`);
        console.log(`💵 輸入金額: ${inputAmount} satoshis (${inputAmount / 100000000} BTC)`);

        // 輸出地址和金額
        const outputAddress = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'; // 創世區塊地址
        const outputAmount = 99000000; // 0.99 BTC (扣除手續費)
        const fee = inputAmount - outputAmount;

        console.log(`📤 輸出地址: ${outputAddress}`);
        console.log(`💵 輸出金額: ${outputAmount} satoshis (${outputAmount / 100000000} BTC)`);
        console.log(`💸 手續費: ${fee} satoshis (${fee / 100000000} BTC)`);

        // 創建交易構建器
        const psbt = new bitcoin.Psbt({ network: bitcoin.networks.bitcoin });

        console.log('\n🔨 第三步：構建交易');
        console.log('-'.repeat(50));

        // 添加輸入
        console.log(`🔗 前一個交易十六進制: ${prevTxHex}`);
        
        psbt.addInput({
            hash: prevTxId,
            index: prevTxIndex,
            nonWitnessUtxo: Buffer.from(prevTxHex, 'hex'),
        });

        console.log('✅ 已添加輸入到交易中');

        // 添加輸出
        psbt.addOutput({
            address: outputAddress,
            value: outputAmount,
        });

        console.log('✅ 已添加輸出到交易中');

        // 顯示交易的原始數據（簽章前）
        console.log('\n📄 第四步：交易原始數據（簽章前）');
        console.log('-'.repeat(50));
        
        // 獲取未簽章的交易
        const tempTx = psbt.data.globalMap.unsignedTx;
        if (tempTx) {
            const unsignedHex = tempTx.toBuffer().toString('hex');
            console.log(`🔤 未簽章交易十六進制: ${unsignedHex}`);
            console.log(`📏 交易大小: ${unsignedHex.length / 2} 字節`);
        }

        // 簽章過程
        console.log('\n✍️ 第五步：交易簽章過程');
        console.log('-'.repeat(50));

        // 創建簽章雜湊（通過獲取要簽章的數據）
        console.log(`🧮 準備對輸入 0 進行簽章`);
        console.log(`📝 簽章類型: SIGHASH_ALL (0x01)`);
        console.log(`🎯 要簽章的內容: 交易的所有輸入和輸出的雜湊值`);

        // 簽章交易
        psbt.signInput(0, this.keyPair);
        
        console.log(`✒️ 使用私鑰進行ECDSA簽章`);
        console.log(`� 簽章公鑰: ${this.keyPair.publicKey.toString('hex')}`);

        psbt.finalizeAllInputs();

        console.log('\n🎉 第六步：完成簽章');
        console.log('-'.repeat(50));

        // 獲取最終的交易（忽略手續費警告，因為這是演示）
        const finalTx = psbt.extractTransaction(true);
        const finalTxHex = finalTx.toHex();
        const txId = finalTx.getId();

        console.log(`🆔 交易ID (TXID): ${txId}`);
        console.log(`🔤 最終交易十六進制: ${finalTxHex}`);
        console.log(`📏 最終交易大小: ${finalTxHex.length / 2} 字節`);

        // 解析交易結構
        this.parseTransactionStructure(finalTxHex);

        // 驗證簽章
        console.log('\n🔍 第七步：簽章驗證');
        console.log('-'.repeat(50));
        
        try {
            // 驗證交易的有效性
            const isValid = this.verifyTransactionSignature(finalTx, 0, inputAmount);
            console.log(`✅ 簽章驗證結果: ${isValid ? '有效' : '無效'}`);
        } catch (error) {
            console.log(`❌ 簽章驗證失敗: ${error}`);
        }

        console.log('\n📚 教學總結');
        console.log('-'.repeat(50));
        console.log('1. 私鑰生成了唯一的公鑰和地址');
        console.log('2. 交易包含輸入（UTXO）和輸出');
        console.log('3. 簽章過程使用ECDSA算法對交易雜湊進行簽名');
        console.log('4. 簽章確保只有私鑰持有者才能花費UTXO');
        console.log('5. 任何人都可以使用公鑰驗證簽章的有效性');
    }

    /**
     * 創建模擬的前一個交易十六進制字符串，確保雜湊匹配
     */
    private createMockPrevTxHex(expectedTxId: string, amount: number): string {
        // 創建一個交易，其雜湊值正好是expectedTxId
        // 這需要一些技巧，我們直接構建一個有效的交易結構
        
        // 為了簡化，我們創建一個最小的有效交易
        const outputScript = bitcoin.address.toOutputScript(this.address, bitcoin.networks.bitcoin);
        const outputScriptHex = outputScript.toString('hex');
        
        // 構建交易結構
        let txHex = '';
        txHex += '02000000'; // version (4 bytes)
        txHex += '01'; // input count (1 byte)
        txHex += '0000000000000000000000000000000000000000000000000000000000000000'; // prev hash (32 bytes)
        txHex += 'ffffffff'; // prev index (4 bytes)
        txHex += '00'; // script length (1 byte)
        txHex += 'ffffffff'; // sequence (4 bytes)
        txHex += '01'; // output count (1 byte)
        
        // 金額 (8 bytes, little-endian)
        const amountBuffer = Buffer.allocUnsafe(8);
        amountBuffer.writeBigUInt64LE(BigInt(amount), 0);
        txHex += amountBuffer.toString('hex');
        
        // 輸出腳本
        const scriptLength = (outputScriptHex.length / 2).toString(16).padStart(2, '0');
        txHex += scriptLength;
        txHex += outputScriptHex;
        txHex += '00000000'; // locktime (4 bytes)
        
        // 計算這個交易的實際雜湊
        const txBuffer = Buffer.from(txHex, 'hex');
        const hash1 = bitcoin.crypto.sha256(txBuffer);
        const hash2 = bitcoin.crypto.sha256(hash1);
        const actualTxId = hash2.reverse().toString('hex');
        
        console.log(`📊 構建的交易雜湊: ${actualTxId}`);
        console.log(`📊 期望的交易雜湊: ${expectedTxId}`);
        
        // 如果雜湊不匹配，我們需要調整交易內容
        // 為了演示目的，我們使用實際計算出的雜湊
        return txHex;
    }

    /**
     * 解析交易結構
     */
    private parseTransactionStructure(txHex: string): void {
        console.log('\n🔬 交易結構解析');
        console.log('-'.repeat(50));
        
        let offset = 0;
        
        // 版本號 (4 bytes)
        const version = txHex.substr(offset, 8);
        offset += 8;
        console.log(`📌 版本號: ${version} (${parseInt(version, 16)})`);
        
        // 輸入數量 (1 byte, varint)
        const inputCount = txHex.substr(offset, 2);
        offset += 2;
        console.log(`📥 輸入數量: ${inputCount} (${parseInt(inputCount, 16)})`);
        
        // 前一個交易雜湊 (32 bytes, little-endian)
        const prevTxHash = txHex.substr(offset, 64);
        offset += 64;
        console.log(`🔗 前一個交易雜湊: ${prevTxHash}`);
        
        // 前一個交易輸出索引 (4 bytes)
        const prevTxIndex = txHex.substr(offset, 8);
        offset += 8;
        console.log(`📍 輸出索引: ${prevTxIndex}`);
        
        // 腳本長度
        const scriptLength = txHex.substr(offset, 2);
        offset += 2;
        const scriptLengthNum = parseInt(scriptLength, 16);
        console.log(`📜 腳本長度: ${scriptLength} (${scriptLengthNum} bytes)`);
        
        // 解鎖腳本
        const unlockScript = txHex.substr(offset, scriptLengthNum * 2);
        offset += scriptLengthNum * 2;
        console.log(`🔓 解鎖腳本: ${unlockScript}`);
        
        // 序列號 (4 bytes)
        const sequence = txHex.substr(offset, 8);
        offset += 8;
        console.log(`🔢 序列號: ${sequence}`);
        
        // 輸出數量 (1 byte)
        const outputCount = txHex.substr(offset, 2);
        offset += 2;
        console.log(`📤 輸出數量: ${outputCount} (${parseInt(outputCount, 16)})`);
        
        // 輸出金額 (8 bytes)
        const outputValue = txHex.substr(offset, 16);
        offset += 16;
        console.log(`💰 輸出金額: ${outputValue}`);
        
        // 輸出腳本長度
        const outputScriptLength = txHex.substr(offset, 2);
        offset += 2;
        const outputScriptLengthNum = parseInt(outputScriptLength, 16);
        console.log(`📜 輸出腳本長度: ${outputScriptLength} (${outputScriptLengthNum} bytes)`);
        
        // 輸出腳本
        const outputScript = txHex.substr(offset, outputScriptLengthNum * 2);
        offset += outputScriptLengthNum * 2;
        console.log(`🔒 鎖定腳本: ${outputScript}`);
        
        // 鎖定時間 (4 bytes)
        const locktime = txHex.substr(offset, 8);
        console.log(`⏰ 鎖定時間: ${locktime} (${parseInt(locktime, 16)})`);
    }

    /**
     * 驗證交易簽章
     */
    private verifyTransactionSignature(tx: bitcoin.Transaction, inputIndex: number, inputAmount: number): boolean {
        try {
            // 獲取輸入腳本
            const input = tx.ins[inputIndex];
            const script = input.script;
            
            // 解析腳本以獲取簽章和公鑰
            const chunks = bitcoin.script.decompile(script);
            if (!chunks || chunks.length < 2) {
                return false;
            }
            
            const signature = chunks[0] as Buffer;
            const publicKey = chunks[1] as Buffer;
            
            // 移除SIGHASH類型字節
            const signatureWithoutHashType = signature.slice(0, -1);
            
            // 重新計算簽章雜湊
            const hashType = bitcoin.Transaction.SIGHASH_ALL;
            const signatureHash = tx.hashForSignature(inputIndex, 
                bitcoin.payments.p2pkh({ pubkey: publicKey }).output!, 
                hashType);
            
            // 驗證簽章
            return ecc.verify(signatureHash, publicKey, signatureWithoutHashType);
        } catch (error) {
            console.log(`驗證過程中發生錯誤: ${error}`);
            return false;
        }
    }
}

// 主程序執行
function main() {
    try {
        const demo = new BitcoinTransactionDemo();
        demo.createAndSignTransaction();
        
        console.log('\n🎓 程序執行完成！');
        console.log('這個演示展示了比特幣交易簽章的完整過程，包括：');
        console.log('- 密鑰生成和地址計算');
        console.log('- 交易結構構建');
        console.log('- ECDSA數字簽章');
        console.log('- 交易序列化和雜湊計算');
        console.log('- 簽章驗證');
        
    } catch (error) {
        console.error('❌ 程序執行錯誤:', error);
    }
}

// 執行主程序
main();
