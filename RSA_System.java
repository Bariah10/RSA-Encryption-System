package RSA_System;


public class RSA_System {

	public static int[] String_to_intArray(String s) {
		int arr[] = new int[s.length()];
		s = s.toLowerCase(); 
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt(i);
			int n = ch - 'a' + 1; // miens to start from 1
			arr[i] = n;
			}

		return arr;
	}

//------------------------------------------------------
	public static long modularExponentiation(long base, long exponent, long modulus) {
        long res = 1; // 1 cus no effect in multiplying
        base = base % modulus; // less num of base avoid overflow

        while (exponent > 0) {

            if ((exponent & 1) == 1) { // check last digit
                res = (res * base) % modulus; //base^(2^position)
            }

            base = (base * base) % modulus;
            exponent = exponent / 2; // go to next digit
        }

        return res;
    }

//------------------------------------------------------
	public static int[] LCG(int seed, int quantity) {
		final int A = 1664525;
		final int C = 1013904223;
		int[] result = new int[quantity];
	    int x = seed;
	    
	    for (int i = 0; i < quantity; i++) {
	    	x = A * x + C; // int overflow here behaves like modulo 2^32
	    	result[i] = x;
	    }
	    return result;
	} 
	public static boolean isProbablePrime(long n) {
	    if (n < 2) return false;
	    if (n == 2 || n == 3) return true;
	    if (n % 2 == 0) return false; // even numbers > 2 are composite

	    int bound = 10000;
	    if (!trialDivisionUpToBound(n, bound)) return false; // stage 1: trial division

	    int[] bases = {2, 3, 5};
	    return fermatTest(n, bases); // stage 2: Fermat test
	}
// -----------------------------------------------------------

	public static boolean trialDivisionUpToBound(long n, int bound) {
	    if (n < 2) return false;
	    
	    // Take the minimum between sqrt(n) and bound
	    long limit = Math.min((long) Math.sqrt(n), bound);
	    
	    // Check divisibility by 2 first (even though isProbablePrime already did)
	    if (n % 2 == 0 && n > 2) return false;
	    
	    // Check only odd divisors
	    for (long d = 3; d <= limit; d += 2) {
	        if (n % d == 0) return false; // found a divisor -> composite
	    }
	    return true; // no small divisors found
	}
// ----------------------------------------------------------
	public static boolean fermatTest(long n, int[] bases) {
	    if (n <= 1) return false;
	    
	    for (int a : bases) {
	        // Skip if base is out of valid range
	        if (a < 2 || a >= n) continue;
	        
	        // If gcd(a, n) ≠ 1, then n is composite
	        if (gcd(a, n) != 1) return false;
	        
	        // Compute a^(n-1) mod n using modular exponentiation
	        long r = modularExponentiation(a, n - 1, n);
	        if (r != 1) return false; // fails Fermat test -> composite
	    }
	    return true; // passed all bases -> probable prime
	}
// ---------------------------------------------------------
	private static long gcd(long a, long b) {
	    a = Math.abs(a);
	    b = Math.abs(b);
	    while (b != 0) {
	        long t = a % b;
	        a = b;
	        b = t;
	    }
	    return a;
	}

//------------------------------------------------------
	public static long extendedEuclideanAlgorithm(long e, long m) {
	    long old_r = e, r = m;
	    long old_s = 1, s = 0;
	    long old_t = 0, t = 1;

	    while (r != 0) {
	        long q = old_r / r;

	        long temp = old_r;
	        old_r = r;
	        r = temp - q * r;

	        temp = old_s;
	        old_s = s;
	        s = temp - q * s;

	        temp = old_t;
	        old_t = t;
	        t = temp - q * t;
	    }

	    // old_r = gcd(e,m)
	    // old_s = modular inverse

	    if (old_s < 0) {//In case the inverse is a negative number
	        old_s += m;
	    }

	    return old_s;
	}

//------------------------------------------------------
	public static class KeyPair {
	    public final long n, e, d;
	    public KeyPair(long n, long e, long d) {
	        this.n = n;
	        this.e = e;
	        this.d = d;
	    }
	}
	public static KeyPair generateKeys() {

		    // Generate p and q (prime numbers) 
		    int[] candidates = LCG(12345, 1000);   // random pool

		    long p = 0, q = 0;

		    for (int num : candidates) {
		        long candidate = Math.abs((long) num);

		     // Restrict to small odd candidates to keep n in int range
		        if (candidate > 2 && candidate < 10000 && candidate % 2 != 0 && isProbablePrime(candidate)) {
		            if (p == 0) {
		                p = candidate;
		            } else if (q == 0 && candidate != p) {
		                q = candidate;
		                break ; }  } }
		 // Fallback to fixed small primes if LCG did not find suitable ones
		    if (p == 0 || q == 0) {
		        p = 3557;  // prime
		        q = 2579;  // prime
		    }
		    // Compute modulus n and m = (p-1)(q-1)
		    long n = p * q;
		    long m = (p - 1) * (q - 1);
		    // Choose e (public exponent) 
		    long e = 3;
		    while (gcd(e, m) != 1) {
		        e += 2; // try next odd number
		    }
		    // Compute d (private exponent)
		    long d = extendedEuclideanAlgorithm(e, m);

		    // Return KeyPair 
		    return new KeyPair(n, e, d);
	}

//------------------------------------------------------
	 // Encrypts a plaintext message using the public key (e, n)
    public long[] encrypt(String message, int e, int n) {
    
    int[] numbers = String_to_intArray(message);
    
    int size = numbers.length ;
    long[] ciphertext = new long[size];
    
    for(int i =0 ; i< size ; i++)
    ciphertext[i] = modularExponentiation(numbers[i] , e, n);


        return ciphertext;
    }
  //------------------------------------------------------
    // Decrypts a ciphertext array using the private key (d, n)
    public String decrypt(long[] ciphertext, int d, int n) {
    
    int[] numbers = new int[ciphertext.length];

    for (int i = 0; i < ciphertext.length; i++) 
        numbers[i] = (int) modularExponentiation(ciphertext[i], d, n);
    

    return IntArray_to_String(numbers);
    }
    //------------------------------------------------------
 // Converts an array of integers back to text
    // Example: [8, 5, 12, 12, 15] -> "hello"
    public String IntArray_to_String(int[] arr) {
    String str = "";
    
     for(int i : arr)
     if (  i >= 1 && i <= 26) {             
      char ch= (char) ('a' + i - 1);
     str+= ch ; }

        return str;
    }
  //------------------------------------------------------   
	public static void main(String[] args) {
		RSA_System rsa = new RSA_System();
		
	System.out.println();
	System.out.println("-------- Testing LCG (Random Number Generator) --------");
	int[] randomNumbers = LCG(12345, 5);
	System.out.println("LCG sequence: " + java.util.Arrays.toString(randomNumbers));
	
	System.out.println();	    
	System.out.println("-------- Testing GCD Method --------");
	System.out.println("gcd(48, 18) = " + gcd(48, 18) );
	System.out.println("gcd(17, 13) = " + gcd(17, 13) );
	
	System.out.println();	    
	System.out.println("-------- Testing Trial Division --------");
	System.out.println("trialDivisionUpToBound(17, 100) = " + trialDivisionUpToBound(17, 100) );
	System.out.println("trialDivisionUpToBound(15, 100) = " + trialDivisionUpToBound(15, 100) );
	
	System.out.println();    
	System.out.println("-------- Testing Fermat Test --------");
	int[] bases = {2, 3, 5};
	System.out.println("fermatTest(17, bases) = " + fermatTest(17, bases) + " (17 is prime)");
	System.out.println("fermatTest(15, bases) = " + fermatTest(15, bases) + " (15 is composite)");
	
	System.out.println();	    
	System.out.println("-------- Testing isProbablePrime (Combined) --------");
	System.out.println("isProbablePrime(17) = " + isProbablePrime(17) + " (17 is prime)");
	System.out.println("isProbablePrime(15) = " + isProbablePrime(15) + " (15 is composite)");
	System.out.println("isProbablePrime(7919) = " + isProbablePrime(7919) + " (7919 is prime)");
	
	System.out.println();	    
	System.out.println("-------- Testing Modular Exponentiation --------");
	long result1 = modularExponentiation(3, 94, 17);
	long result2 = modularExponentiation(3, 200, 50);
	System.out.println("3^94 mod 17 = " + result1);
	System.out.println("3^200 mod 50 = " + result2);
	
	System.out.println();	    
	System.out.println("-------- Testing Extended Euclidean Algorithm --------");
	long inverse = extendedEuclideanAlgorithm(3, 11);
	System.out.println("Modular inverse of 3 mod 11 = " + inverse + " (should be 4)");
	
	System.out.println();	    
	System.out.println("-------- Testing RSA Key Generation --------");
	KeyPair key = generateKeys();
	int e = (int) key.e;
	int n = (int) key.n;
	int d = (int) key.d;
	System.out.println("Generated Keys - n: " + n + ", e: " + e + ", d: " + d);
	
	System.out.println();	    
	System.out.println("-------- Testing String Conversion --------");
	String testMsg = "hello";
	int[] intArray = String_to_intArray(testMsg);
	String backToString = rsa.IntArray_to_String(intArray);
	System.out.println("Original: '" + testMsg + "' -> IntArray: " + java.util.Arrays.toString(intArray));
	System.out.println("Back to string: '" + backToString + "'");
	
	System.out.println();	    
	System.out.println("-------- Testing RSA Encryption/Decryption --------");
	String msg = "maram";
	long[] encrypted = rsa.encrypt(msg, e, n);
	System.out.println("Encrypted '" + msg + "' = " + java.util.Arrays.toString(encrypted));

	String decrypted = rsa.decrypt(encrypted, d, n);
	System.out.println("Decrypted = '" + decrypted + "'");
		
    }

}
