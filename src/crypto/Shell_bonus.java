package crypto;
import java.util.Scanner;
public class Shell_bonus {

	public static void main(String[] args) {
		Scanner scan = new Scanner(System.in);
		char reponse1;
		int reponse2=0;
		char reponse3;
		String texte;
		String cipherText="";
		String cle="";
		boolean isFinished =false ;
		boolean estPasseParEncrypt=false;
		
		do {
			System.out.println("Que souhaitez-vous faire ? ( 'E' pour encoder un texte.'D' pour decrypter "
					+ "un texte)");
			reponse1=scan.nextLine().charAt(0);
			
			if(reponse1=='E' || reponse1=='e') {
				
				do{
					System.out.println("Avec quelle methode d'encryptage souhaitez-vous"
				
						+" encypter votre texte? (Veuillez Introduire le nombre 5 pour afficher"
						+ " l'aide.)");
				reponse2=scan.nextInt();
				if(reponse2==5) {
				System.out.println("Notre programme vous propose d'encrypter votre texte"
						+System.lineSeparator() +"avec 5 methodes differentes. Vous devez introduire le nombre "
						+ System.lineSeparator()+"correspendant a chaque methode comme suit : 0 = Caesar, 1 = Vigenere, "
						+ "2 = XOR, 3 = One time pad, 4 = CBC.");
				System.out.println("----------------------------------------------------");
				                }
				}while(reponse2>4 || reponse2<0);
				scan.nextLine();
				System.out.println("Veuillez Introduire votre texte: ");
				texte=scan.nextLine();
				System.out.println("Veuillez introduire une cle: ");
				cle=scan.nextLine();
				System.out.println("Voici votre texte encypte: ");
				cipherText=Encrypt.encrypt(texte,cle,reponse2);
				System.out.println(cipherText);
				if(! (reponse2==3)) {
				System.out.println("Voulez-vous decrypter votre message? (O/N)");
				reponse3=scan.nextLine().charAt(0);
				if(reponse3=='O'|| reponse3=='o') {
					
					reponse1='D';
					estPasseParEncrypt=true;
				}
				}
			}
			if(reponse1=='D' || reponse1=='d') {
				if(estPasseParEncrypt) {
					if(reponse2==4) {
						System.out.println(Helper.bytesToString(Decrypt.decryptCBC(Helper.stringToBytes(cipherText), Helper.stringToBytes(cle))));
					}
					else{System.out.println(Decrypt.breakCipher(cipherText,reponse2));}
				}
				else {
					do{
						System.out.println("Avec quelle methode de decryptage souhaitez-vous"
					
							+" decrypter votre texte? (Veuillez Introduire le nombre 3 pour afficher"
							+ " l'aide.)");
					reponse2=scan.nextInt();
					if(reponse2==3) {
					System.out.println("Notre programme vous propose de decrypter votre texte"
							+ System.lineSeparator()+"avec 3 methodes differentes. Vous devez introduire le nombre "
							+ System.lineSeparator()+"correspendant a chaque methode comme suit : 0 = CaesarAvecFrequences, 1 = VigenereAvecFrequences, "
							+ "2 = XOR_AvecForce(non recommendee)");
					
					System.out.println("----------------------------------------------------");
					                }
				
					}while(reponse2>2 || reponse2<0);
					
					System.out.println("Veuillez Introduire votre texte Encrypte: ");
					scan.nextLine();
					texte=scan.nextLine();
				
					System.out.println("Voici votre texte Decrypte: ");
					System.out.println(Decrypt.breakCipher(texte,reponse2));
					
				}
			}
		System.out.println();
		System.out.println("----------------------------------------------------");
		System.out.println("Souhaitez-vous continuer avec notre programme super sophistique: (O/N)");
		reponse3=scan.nextLine().charAt(0);
		if(reponse3=='O'|| reponse3=='o') {
			isFinished=true;
		}else {
			isFinished=false;
			System.out.println("Merci de votre confiance! A tres bientot!");
		}
			
		estPasseParEncrypt=false;
		}while(isFinished);

	}

}
