package rc6;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.io.FileWriter;


public class Driver{
	
	private static int r = 20;
	private static int p32 = 0xB7E15163;
	private static int q32 = 0x9E3779B9;
	private static int[] S;
	
	private static int rotateRight(int value, int val2){
		int retVal = (value >>> val2) | (value << (32 - val2));
		return retVal;
	}
	private static int rotateLeft(int value, int val2){
		int retVal = (value << val2) | (value >>> (32 - val2));
		return retVal;
	}
	
	private static byte[] encrypt (byte[] input, byte[] key){
		S = generateKey(key);
		byte[] out = new byte[16];
		int A = (input[0] & 0xFF) |
				((input[1] & 0xFF) << 8) |
				((input[2] & 0xFF) << 16) |
				(input[3] << 24);
		int B = (input[4] & 0xFF) |
				((input[5] & 0xFF) << 8) |
			 	((input[6] & 0xFF) << 16) |
				(input[7] << 24);
		int C = (input[8] & 0xFF) |
				((input[9] & 0xFF) << 8) |
				((input[10] & 0xFF) << 16) |
				(input[11] << 24);
		int D = (input[12] & 0xFF) |
				((input[13] & 0xFF) << 8) |
				((input[14] & 0xFF) << 16) |
				(input[15] << 24);
					 
		int t, u;
		
		B += S[0];
		D += S[1];
		for(int i = 1; i <= r; i++){
			t = rotateLeft( B*(2 * B + 1), 5 );
			u = rotateLeft( D*(2 * D + 1), 5 );
			A = rotateLeft( (A^t), u ) + S[2 * i];
			C = rotateLeft( (C^u), t ) + S[2 * i + 1];
			t = A; 
			A = B; 
			B = C; 
			C = D; 
			D = t;
		}
		A += S[2 * r + 2];
		C += S[2 * r + 3];
		 
		out[0] = (byte)A;
		out[1] = (byte)(A >>> 8);
		out[2] = (byte)(A >>> 16);
		out[3] = (byte)(A >>> 24);
	
		out[4] = (byte)B;
		out[5] = (byte)(B >>> 8);
		out[6] = (byte)(B >>> 16);
		out[7] = (byte)(B >>> 24);
		
		out[8] = (byte)C;
		out[9] = (byte)(C >>> 8);
		out[10] = (byte)(C >>> 16);
		out[11] = (byte)(C >>> 24);
		
		out[12] = (byte)D;
		out[13] = (byte)(D >>> 8);
		out[14] = (byte)(D >>> 16);
		out[15] = (byte)(D >>> 24);
		return out;
						       
		
	}
	
	private static byte[] decrypt(byte[] input, byte[] key){
		S = generateKey(key);
		byte[] out = new byte[16];
		int A = (input[0] & 0xFF) |
				((input[1] & 0xFF) << 8) |
				((input[2] & 0xFF) << 16) |
				(input[3] << 24);
		int B = (input[4] & 0xFF) |
				((input[5] & 0xFF) << 8) |
			 	((input[6] & 0xFF) << 16) |
				(input[7] << 24);
		int C = (input[8] & 0xFF) |
				((input[9] & 0xFF) << 8) |
				((input[10] & 0xFF) << 16) |
				(input[11] << 24);
		int D = (input[12] & 0xFF) |
				((input[13] & 0xFF) << 8) |
				((input[14] & 0xFF) << 16) |
				(input[15] << 24);
					 
		int t, u;
		
		C -= S[2 * r + 3];
		A -= S[2 * r + 2];
		for(int i = r; i >= 1; i--){
			
			t = D; 
			D = C;
			C = B;
			B = A;
			A = t; 
			 
			
			u = rotateLeft( D*(2 * D + 1), 5);
			t = rotateLeft( B*(2 * B + 1), 5);
			C = rotateRight(C-S[2 * i + 1], t)^u;
			A = rotateRight(A-S[2*i], u)^t;
			
			
		}
		D -= S[1];
		B -= S[0];
		 
		out[0] = (byte)A;
		out[1] = (byte)(A >>> 8);
		out[2] = (byte)(A >>> 16);
		out[3] = (byte)(A >>> 24);
	
		out[4] = (byte)B;
		out[5] = (byte)(B >>> 8);
		out[6] = (byte)(B >>> 16);
		out[7] = (byte)(B >>> 24);
		
		out[8] = (byte)C;
		out[9] = (byte)(C >>> 8);
		out[10] = (byte)(C >>> 16);
		out[11] = (byte)(C >>> 24);
		
		out[12] = (byte)D;
		out[13] = (byte)(D >>> 8);
		out[14] = (byte)(D >>> 16);
		out[15] = (byte)(D >>> 24);
		return out;
	}
	
	private static int[] generateKey(byte[] userKey){
		int c = userKey.length / 4;
		int sizeOfS = 2 * r + 4;
		
		int[] S = new int[sizeOfS];
		
		int[] L = new int[c];
		int off = 0;
		for(int i=0; i < c; i++)
			L[i] = (userKey[off++]&0xFF) |
					((userKey[off++]&0xFF) <<  8) |
					((userKey[off++]&0xFF) << 16) |
					((userKey[off++]&0xFF) << 24);
		
		S[0] = p32;
		for (int i = 1; i < sizeOfS; i++){
			S[i] = S[i - 1] + q32;
		}
		int val1 = 0;
		int val2 = 0;
		int i = 0;
		int j = 0;
		int v = 3 * Math.max(c, sizeOfS);
		
		for (int k = 0; k < v; k++){
			val1 = 	S[i] = rotateLeft((S[i] + val1 + val2), 3);
			val2 = L[j] =  rotateLeft(L[j] + val1 + val2, val1 + val2);
			i = (i + 1) % sizeOfS;
			j = (j + 1) % c;
			
		}
		return S;
			
		
	}
	
	public static void main(String[] args) throws IOException{
			
			String inputPath = null;
			String outputPath = null;
			try {
				inputPath = args[0];
				outputPath = args[1];
			}
			catch (ArrayIndexOutOfBoundsException e){
				System.err.println("Could not find specified input file");
				System.exit(0);
			}
			URL inputUrl = Driver.class.getClassLoader().getResource(inputPath);
			URL outputUrl = Driver.class.getClassLoader().getResource(outputPath);
			System.out.println("Output written to " + outputUrl);
			FileReader input = null;
			BufferedReader buffer = null;
			FileWriter output = null;
			
			try {
				input = new FileReader(inputUrl.getPath());
				buffer = new BufferedReader(input);
				output = new FileWriter(outputUrl.getPath());
				//output.write("test");
				String thisLine;
				thisLine = buffer.readLine();
				while(thisLine != null){
					byte[] plaintext = new byte[16];
					byte[] ciphertext = new byte[16];
					byte[] userKey = null;
					String[] tokens = thisLine.split("\\s+");
					if (tokens[0].equals("Encryption")){
						thisLine = buffer.readLine();
						tokens = thisLine.split("\\s+");
						for (int i = 0; i < plaintext.length; i++){
							plaintext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
							//System.out.println(plaintext[i]);
						}
						thisLine = buffer.readLine();
						tokens = thisLine.split("\\s+");
						userKey = new byte[tokens.length - 1];
						for (int i = 0; i < userKey.length; i++){
							userKey[i] = (byte)Integer.parseInt(tokens[i + 1], 16);
							//System.out.println(userKey[i]);
						}
						byte[] result = encrypt(plaintext, userKey);
						//for (int i = 0; i < result.length; i++)
							//System.out.print(result[i] + " ");
						output.write("ciphertext: ");
						for (int i = 0; i < result.length; i++){
							output.write(Integer.toHexString(result[i] & 0xFF));
							output.write(" ");
						}
						thisLine = buffer.readLine();
						
					}
					else if(tokens[0].equals("Decryption")){
						thisLine = buffer.readLine();
						tokens = thisLine.split("\\s+");
						for (int i = 0; i < ciphertext.length; i++){
							ciphertext[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
							//System.out.println(ciphertext[i]);
						}
						thisLine = buffer.readLine();
						tokens = thisLine.split("\\s+");
						userKey = new byte[tokens.length - 1];
						for (int i = 0; i < userKey.length; i++){
							userKey[i] = (byte) Integer.parseInt(tokens[i + 1], 16);
							//System.out.println(userKey[i]);
						}
						byte[] result = decrypt(ciphertext, userKey);
						//for (int i = 0; i < result.length; i++)
							//System.out.print(result[i] + " ");
						output.write("plaintext: ");
						for (int i = 0; i < result.length; i++){
							output.write(Integer.toHexString(result[i] & 0xFF));
							output.write(" ");
						}
						thisLine = buffer.readLine();
						
					}
				}
				
			}
			catch (FileNotFoundException e){
				System.err.println(e.getMessage());
				System.exit(0);
			}
			catch (IOException e) {
				System.err.println(e.getMessage());
				System.exit(0);
			}
			catch (NullPointerException e){
				System.err.println("Specified input file not found");
				System.exit(0);
			}
			
			finally{
				
				if (input != null) {
					input.close();
				}
				if (buffer != null){
					buffer.close();
				}
				if (output != null) {
					output.close();
				}
			}
			
			
	}
}