package crypto;

import static crypto.Helper.bytesToString;
import static crypto.Helper.stringToBytes;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Decrypt {

	public static final int ALPHABETSIZE = Byte.MAX_VALUE - Byte.MIN_VALUE + 1; // 256
	public static final int APOSITION = 97 + ALPHABETSIZE / 2;

	// source : https://en.wikipedia.org/wiki/Letter_frequency
	public static final double[] ENGLISHFREQUENCIES = { 0.08497, 0.01492, 0.02202, 0.04253, 0.11162, 0.02228, 0.02015,
			0.06094, 0.07546, 0.00153, 0.01292, 0.04025, 0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.07587, 0.06327,
			0.09356, 0.02758, 0.00978, 0.0256, 0.0015, 0.01994, 0.00077 };

	/**
	 * Method to break a string encoded with different types of cryptosystems
	 * 
	 * @param type the integer representing the method to break : 0 = Caesar, 1 =
	 *             Vigenere, 2 = XOR
	 * @return the decoded string or the original encoded message if type is not in
	 *         the list above.
	 */
	public static String breakCipher(String cipher, int type) {
		byte[] cipherByte = Helper.stringToBytes(cipher);

		switch (type) {
		case 0:
			return bytesToString(Encrypt.caesar(cipherByte, caesarWithFrequencies(cipherByte)));
		case 1:
			return bytesToString(Encrypt.vigenere(cipherByte, vigenereWithFrequencies(cipherByte)));
		case 2:
			return arrayToString(xorBruteForce(cipherByte));

		default:
			return "Vous devez introduire 0 1 ou 2";
		}
	}

	/**
	 * Converts a 2D byte array to a String
	 * 
	 * @param bruteForceResult a 2D byte array containing the result of a brute
	 *                         force method
	 */
	public static String arrayToString(byte[][] bruteForceResult) {
		String s = "";
		for (int i = 0; i < bruteForceResult.length; i++) {
			s += bytesToString(bruteForceResult[i]) + System.lineSeparator();
		}

		return s;
	}

	// -----------------------Caesar-------------------------

	/**
	 * Method to decode a byte array encoded using the Caesar scheme This is done by
	 * the brute force generation of all the possible options
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return a 2D byte array containing all the possibilities
	 */
	public static byte[][] caesarBruteForce(byte[] cipher) {
		byte[][] tab = new byte[256][];
		for (int i = 0; i < 256; i++) {
			tab[i] = Encrypt.caesar(cipher, (byte) i);

		}

		return tab;
	}

	/**
	 * Method that finds the key to decode a Caesar encoding by comparing
	 * frequencies
	 * 
	 * @param cipherText the byte array representing the encoded text
	 * @return the encoding key
	 */
	public static byte caesarWithFrequencies(byte[] cipherText) {

		return caesarFindKey(computeFrequencies(cipherText));
	}

	/**
	 * Method that computes the frequencies of letters inside a byte array
	 * corresponding to a String
	 * 
	 * @param cipherText the byte array
	 * @return the character frequencies as an array of float
	 */
	public static float[] computeFrequencies(byte[] cipherText) {
		float[] charFrequencies = new float[256];
		int j = 0;// counts the number of characters (spaces excluded) in the cipherText array
		for (int i = 0; i < cipherText.length; i++) {
			if (cipherText[i] == 32) {
				continue;
			}
			if (cipherText[i] >= 0) {
				charFrequencies[cipherText[i]]++;
			} else if (cipherText[i] < 0) {
				charFrequencies[cipherText[i] + 256]++;

			}
			j++;
		}

		for (int i = 0; i < charFrequencies.length; i++) {
			charFrequencies[i] /= j;

		}

		return charFrequencies;
	}

	/**
	 * Method that finds the key used by a Caesar encoding from an array of
	 * character frequencies
	 * 
	 * @param charFrequencies the array of character frequencies
	 * @return the key
	 */
	public static byte caesarFindKey(float[] charFrequencies) {
		double r = 0, s = 0; // the variable r is used to stock the scalar product of each loop, whereas the
								// variable s
		// to stock the temporary largest scalar product until then found
		byte key = 0;
		for (int j = 0; j < charFrequencies.length; j++) {
			for (int i = 0; i < ENGLISHFREQUENCIES.length; i++) {
				if (j + i > 255) {
					r += (charFrequencies[(j + i) - 256] * ENGLISHFREQUENCIES[i]);
				} else {
					r += (charFrequencies[j + i] * ENGLISHFREQUENCIES[i]);
				}
			}
			if (Double.compare(s, r) >= 0) {
				r = 0;
			} else {
				s = r;
				r = 0;
				key = (byte) (-j + 97);
			}

		}

		return key;
	}

	// -----------------------XOR-------------------------

	/**
	 * Method to decode a byte array encoded using a XOR This is done by the brute
	 * force generation of all the possible options
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return the array of possibilities for the clear text
	 */
	public static byte[][] xorBruteForce(byte[] cipher) {
		byte[][] tab = new byte[256][];
		for (int i = 0; i < 256; i++) {
			tab[i] = Encrypt.xor(cipher, (byte) i);

		}

		return tab;

	}

	// -----------------------Vigenere-------------------------
	// Algorithm : see https://www.youtube.com/watch?v=LaWp_Kq0cKs
	/**
	 * Method to decode a byte array encoded following the Vigenere pattern, but in
	 * a clever way, saving up on large amounts of computations
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @return the byte encoding of the clear text
	 */
	public static byte[] vigenereWithFrequencies(byte[] cipher) {

		return vigenereFindKey(removeSpaces(cipher), vigenereFindKeyLength(removeSpaces(cipher)));
	}

	/**
	 * Helper Method used to remove the space character in a byte array for the
	 * clever Vigenere decoding
	 * 
	 * @param array the array to clean
	 * @return a List of bytes without spaces
	 */
	public static List<Byte> removeSpaces(byte[] array) {
		List<Byte> list = new ArrayList<Byte>();
		for (int iz = 0; iz < array.length; iz++) {
			if (array[iz] == 32) {
				continue;
			}
			list.add(array[iz]);
		}
		return list;
	}

	/**
	 * Method that computes the key length for a Vigenere cipher text.
	 * 
	 * @param cipher the byte array representing the encoded text without space
	 * @return the length of the key
	 */
	public static int vigenereFindKeyLength(List<Byte> cipher) {
		// STEP 1:
		// compare the cipher text with a shifted version of itself (for loop).
		// for each shift compute how many letters coincide (realised by the variable
		// "coincidences").
		int coincidences = 0;
		int[] coincidencesTab = new int[cipher.size() - 1];
		for (int j = 1; j < cipher.size(); j++) {
			for (int s = 0; s < cipher.size() - j; s++) {
				if (cipher.get(s) == cipher.get(j + s)) {
					coincidences++;
				}
			}
			coincidencesTab[j - 1] = coincidences;
			coincidences = 0;
		}
		// STEP 2
		// we find the local maxima of the first half of the table "coincidencesTab".

		List<Integer> maxLoc = new ArrayList<Integer>();
		for (int sb = 0; sb < (int) Math.ceil(coincidencesTab.length / 2); sb++) {
			if (sb == 0 && coincidencesTab[sb] > coincidencesTab[sb + 1]
					&& coincidencesTab[sb] > coincidencesTab[sb + 2]) {
				maxLoc.add(sb);
			} else if (sb == 1 && coincidencesTab[sb] > coincidencesTab[sb + 1]
					&& coincidencesTab[sb] > coincidencesTab[sb + 2] && coincidencesTab[sb] > coincidencesTab[sb - 1]) {
				maxLoc.add(sb);
			} else if (coincidencesTab[sb] > coincidencesTab[sb + 1] && coincidencesTab[sb] > coincidencesTab[sb + 2]
					&& coincidencesTab[sb] > coincidencesTab[sb - 1] && coincidencesTab[sb] > coincidencesTab[sb - 2]) {
				maxLoc.add(sb);
			}
		}
		// STEP 3:
		// we create the map "map" with the following idea: we make each distance
		// (Integer), between two consecutive indices,
		// a key for which we associate a value that is the number of times the key
		// occurs.
		int distance = 0;
		List<Integer> valuesOfDistances = new ArrayList<Integer>();
		Map<Integer, Integer> map = new HashMap<>();
		for (int i = 0; i < maxLoc.size() - 1; i++) {
			distance = maxLoc.get(i + 1) - maxLoc.get(i);
			if (map.containsKey(distance)) {
				map.replace(distance, map.get(distance) + 1);
			} else {
				map.put(distance, 1);
				valuesOfDistances.add(distance);
			}
		}

		int max = 0;// the variable "max" stores the the key that has the maximum value.
		int u = 0;// the variable "u" stores the value.
		for (int i = 0; i < valuesOfDistances.size(); i++) {

			if (u > map.get(valuesOfDistances.get(i))) {
				continue;
			} else if (u == map.get(valuesOfDistances.get(i))) {
				max = Math.max(max, valuesOfDistances.get(i));
			} else {
				u = map.get(valuesOfDistances.get(i));
				max = valuesOfDistances.get(i);
			}

		}

		return max;
	}

	/**
	 * Takes the cipher without space, and the key length, and uses the dot product
	 * with the English language frequencies to compute the shifting for each letter
	 * of the key
	 * 
	 * @param cipher    the byte array representing the encoded text without space
	 * @param keyLength the length of the key we want to find
	 * @return the inverse key to decode the Vigenere cipher text
	 */
	public static byte[] vigenereFindKey(List<Byte> cipher, int keyLength) {
		byte[][] intermediateArray = new byte[keyLength][];// the bi-dimensional array stores the bytes encoded with the
															// same key
		List<Byte> miniCipher = new ArrayList<Byte>();// as we can not know how many bytes are encoded with the same
														// key,
		// we use this dynamic array to store the bytes encoded with the same key.
		byte[] result = new byte[keyLength];
		for (int z = 0; z < keyLength; z++) {

			for (int s = z; s < cipher.size(); s = s + keyLength) {

				miniCipher.add(cipher.get(s));
			}
			intermediateArray[z] = new byte[miniCipher.size()];
			for (int i = 0; i < miniCipher.size(); i++) {
				intermediateArray[z][i] = miniCipher.get(i);
			}
			result[z] = caesarWithFrequencies(intermediateArray[z]);
			miniCipher.clear();

		}

		return result;
	}

	// -----------------------Basic CBC-------------------------

	/**
	 * Method used to decode a String encoded following the CBC pattern
	 * 
	 * @param cipher the byte array representing the encoded text
	 * @param iv     the pad of size BLOCKSIZE we use to start the chain encoding
	 * @return the clear text
	 */
	public static byte[] decryptCBC(byte[] cipher, byte[] iv) {
		int j = 0;
		byte r;// the variable "r" stores the value of the i(th) byte in the cipher tab to
				// decrypt the element
		// after 'iv.length' loop.

		byte cloneCipher[] = Encrypt.cloneArray(cipher);

		byte[] cloneIv = Encrypt.cloneArray(iv);
		for (int i = 0; i < cloneCipher.length; i++) {

			r = cloneCipher[i];
			cloneCipher[i] = (byte) (cloneCipher[i] ^ cloneIv[j]);
			cloneIv[j] = r;
			if (j < cloneIv.length - 1) {
				j++;
			} else {
				j = 0;
			}
		}

		return cloneCipher;

	}

}
