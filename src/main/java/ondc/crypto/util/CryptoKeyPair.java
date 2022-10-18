package ondc.crypto.util;

public class CryptoKeyPair {

	public   CryptoKeyPair(byte[] publickKey,byte[] privateKey){
		this.setPrivateKey(privateKey);
		this.setPublickKey(publickKey);
	}
	
	private byte[] privateKey;
	public byte[] getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}
	public byte[] getPublickKey() {
		return publickKey;
	}
	public void setPublickKey(byte[] publickKey) {
		this.publickKey = publickKey;
	}
	private byte[] publickKey;
	
}
