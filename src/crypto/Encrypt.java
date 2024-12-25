package crypto;

import java.util.Random;
import static crypto.Helper.*;
public class Encrypt {
	
	public static final int CAESAR = 0;
	public static final int VIGENERE = 1;
	public static final int XOR = 2;
	public static final int ONETIME = 3;
	public static final int CBC = 4; 
	
	public static final byte SPACE = 32;
	
	final static Random rand = new Random();
	
	public static byte[] cloneArray(byte[] tab) {
		byte[] tab2=new byte[tab.length];
		for(int i=0; i<tab.length;i++) {
			tab2[i]=tab[i];
		}
		return tab2;
	}	
	
 	//-----------------------General-------------------------
	
	/**
	 * General method to encode a message using a key, you can choose the method you want to use to encode.
	 * @param message the message to encode already cleaned
	 * @param key the key used to encode
	 * @param type the method used to encode : 0 = Caesar, 1 = Vigenere, 2 = XOR, 3 = One time pad, 4 = CBC
	 * 
	 * @return an encoded String
	 * if the method is called with an unknown type of algorithm, it returns the original message
	 */
	public static String encrypt(String message, String key, int type) {
		byte[] tab = Helper.stringToBytes(message);
		byte[] cle = Helper.stringToBytes(key);
		switch (type) {
			case CAESAR: return Helper.bytesToString(caesar(tab, cle[0]));
				
			case VIGENERE: return Helper.bytesToString(vigenere(tab, cle));
						
			case XOR: return Helper.bytesToString(xor(tab, cle[0]));
				
			case ONETIME: return Helper.bytesToString(oneTimePad(tab, cle));
			
			case CBC: return Helper.bytesToString(cbc(tab, cle));
			
			default : return "Veuillez introduire un message, une clÈ et un type valide.";
		}
		
		
	}
	
	
	//-----------------------Caesar-------------------------
	
	/**
	 * Method to encode a byte array message using a single character key
	 * the key is simply added to each byte of the original message
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key, boolean spaceEncoding) {
		assert(plainText != null);
		
		byte[] clonePlainText = cloneArray(plainText);
		
		for(int i=0; i<clonePlainText.length;i++) {
			
			if(clonePlainText[i]==SPACE && !spaceEncoding) {continue; }
			
			clonePlainText[i]+=key;
		                                     }
		
		return clonePlainText; 
	}
	
	/**
	 * Method to encode a byte array message  using a single character key
	 * the key is simply added  to each byte of the original message
	 * spaces are not encoded
	 * @param plainText The byte array representing the string to encode
	 * @param key the byte corresponding to the char we use to shift
	 * @return an encoded byte array
	 */
	public static byte[] caesar(byte[] plainText, byte key) {
		
		return caesar(plainText, key, false); 
	}
	
	//-----------------------XOR-------------------------
	
	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * @param plaintext the byte array representing the string to encode
	 * @param key the byte we will use to XOR
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key, boolean spaceEncoding) {
		
		byte[] clonePlainText = cloneArray(plainText);
		
		for(int i=0; i<clonePlainText.length;i++) {
			
			if(clonePlainText[i]==SPACE && !spaceEncoding) {continue; }
			
			clonePlainText[i]=(byte) (clonePlainText[i]^key);
		                                     }
		
		return clonePlainText; 
	}
	/**
	 * Method to encode a byte array using a XOR with a single byte long key
	 * spaces are not encoded
	 * @param key the byte we will use to XOR
	 * @return an encoded byte array
	 */
	public static byte[] xor(byte[] plainText, byte key) {
		
		return xor(plainText, key, false); 
	}
	//-----------------------Vigenere-------------------------
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @param spaceEncoding if false, then spaces are not encoded
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword, boolean spaceEncoding) {
		
		int j=0;// variable that allows to go all over the keyword array endlessly
		byte[] clonePlainText = cloneArray(plainText);
		
		for(int i=0; i<clonePlainText.length; i++) {
            if(clonePlainText[i]==SPACE && !spaceEncoding) {continue; }
			
            clonePlainText[i]+=keyword[j];
			
	       if(j<keyword.length-1)  { 
	    	             j++;
	                         }
	       else {
	    	   j=0;
	    	   }
		                                       }
		return clonePlainText; 
	}
	
	/**
	 * Method to encode a byte array using a byte array keyword
	 * The keyword is repeated along the message to encode
	 * spaces are not encoded
	 * The bytes of the keyword are added to those of the message to encode
	 * @param plainText the byte array representing the message to encode
	 * @param keyword the byte array representing the key used to perform the shift
	 * @return an encoded byte array 
	 */
	public static byte[] vigenere(byte[] plainText, byte[] keyword) {
		
		return vigenere(plainText, keyword, false); 
	}
	
	
	
	//-----------------------One Time Pad-------------------------
	
	/**
	 * Method to encode a byte array using a one time pad of the same length.
	 *  The method  XOR them together.
	 * @param plainText the byte array representing the string to encode
	 * @param pad the one time pad
	 * @return an encoded byte array
	 */
	public static byte[] oneTimePad(byte[] plainText, byte[] pad) {
		int j=0;
		byte[] clonePlainText = cloneArray(plainText);

		for(int i=0; i<clonePlainText.length; i++) {
            
			
			clonePlainText[i]= (byte)( clonePlainText[i]^pad[j]);
			
	       if(j<pad.length-1)  { 
	    	             j++;
	                         }
	       else {
	    	   j=0;
	    	   }
		 
	}
		return clonePlainText;
	}
	
	
	
	//-----------------------Basic CBC-------------------------
	
	/**
	 * Method applying a basic chain block counter of XOR without encryption method. Encodes spaces.
	 * @param plainText the byte array representing the string to encode
	 * @param iv the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return an encoded byte array
	 */
	public static byte[] cbc(byte[] plainText, byte[] iv) {
		int j=0;
		byte[] clonePlainText = cloneArray(plainText);
		byte[] cloneIV = cloneArray(iv);

		
		
		for(int i=0; i<clonePlainText.length; i++) {
            
			
			clonePlainText[i]= (byte)( clonePlainText[i]^cloneIV[j]);
			cloneIV[j]=clonePlainText[i];
	       if(j<cloneIV.length-1)  { 
	    	             j++;
	                         }
	       else {
	    	   j=0;
	    	   }
		}
		
		return clonePlainText; 
	}
	
	
	/**
	 * Generate a random pad/IV of bytes to be used for encoding
	 * @param size the size of the pad
	 * @return random bytes in an array
	 */
	public static byte[] generatePad(int size) {
		byte[] tab= new byte[size];
		for(int z=0; z<size;z++) {
		byte i= (byte) (-128+rand.nextInt(255));
		tab[z]=i;
		}
		return tab; 

	}

	
	
}
